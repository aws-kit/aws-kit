#!/usr/bin/env python
from __future__ import print_function
import json
import sys
from time import sleep
from six.moves import input
import boto3
import cli.log
import yaml


def match_tag_prefix(logger, tag_list, prefix):
    """
    Check if tag_list matches the prefix.
    """
    if tag_list:
        for tag in tag_list:
            if tag['Key'] == "Name" and tag['Value'].startswith(prefix):
                logger.debug("match_tag_prefix: %s %s %s", prefix, tag['Value'], tag_list)
                return True

    return False


def filter_by_id_or_prefix(log, resources, some_id, vpc_name=None):
    """
    Filter an resource matching "some_id". it should be an resource id exact match, or a Tag:Name prefix match.
    """
    return [r for r in resources if r.id == some_id or match_tag_prefix(log, r.tags, prefix=some_id)
            or (vpc_name is not None and match_tag_prefix(log, r.tags, prefix='%s-%s' % (vpc_name, some_id)))]


def read_config(file_path=None):
    with open(file_path) as f:
        return yaml.load(f, Loader=yaml.BaseLoader)


def get_peers(vpc):
    result = []
    if vpc.accepted_vpc_peering_connections is not None:
        result += [p for p in vpc.accepted_vpc_peering_connections.all()]
    if vpc.requested_vpc_peering_connections is not None:
        result += [p for p in vpc.requested_vpc_peering_connections.all()]
    return result


def find_common_peer(config):
    # find peers that is not deleted. Deleted peer may stay for some time, thus we simply ignore them.
    config['requester']['existing_peer'] = [p for p in config['requester']['all_existing_peers']
                                            if p.accepter_vpc.id == config['accepter']['vpc_resource'].id
                                            and p.status['Code'] != 'deleted']
    config['accepter']['existing_peer'] = [p for p in config['accepter']['all_existing_peers']
                                           if p.requester_vpc.id == config['requester']['vpc_resource'].id
                                           and p.status['Code'] != 'deleted']

    return list(set(config['requester']['existing_peer'] + config['accepter']['existing_peer']))


@cli.log.LoggingApp(stream=sys.stderr, description='''
The app to help setting up the peering between two VPCs.
Ideally, you should prepare your default aws config (or the --profile) as sysadmin account, which 
will be used as requester, and allow sysadmin account to be able to assume to the accepter
account role. The role should be configured in the config yaml file.
''')
def vpc_peering(app):
    if not app.params.config:
        app.log.info("Generating skeleton of config. ")
        config_gen(app.log)
    else:
        config = read_config(app.params.config)
        app.log.debug("Config: %s", json.dumps(config, indent=2, default=str))
        verify_vpcs(app.log, config, app.params.profile, app.params.region)
        app.log.info("Collected VPC details: %s", json.dumps(config, indent=2, default=str))
        analyse_route_config(app.log, config)
        app.log.info("Analysed Subnet config: %s", json.dumps(config, indent=2, default=str))
        common_peer = find_common_peer(config)
        app.log.debug("common_peer found: %s", common_peer)
        if app.params.action == 'apply':
            if common_peer:
                if not app.params.force:
                    app.log.error("There are existing peering between VPCs. Requester VPC:%s, accepter VPC:%s, "
                                  "Peer :%s. Note the peer might be a faulty peer. You can proceed with --force option",
                                  config['requester']['vpc_resource'].id,
                                  config['accepter']['vpc_resource'].id,
                                  common_peer[0])
                    exit(1)
                cleanup_peering(app.log, config)
            create_peering(app.log, config)
        elif app.params.action == 'delete':  # delete
            if not common_peer:
                app.log.info("No peer exists.")
            else:
                cleanup_peering(app.log, config)
        else:  # plan
            if common_peer:
                app.log.warn("Peering already exists as %s. It will be deleted together with all the "
                             "routes associated with it.", common_peer[0].id)
            app.log.warn("A new peer will set up from requester(%s, %s) to accepter(%s, %s)",
                         config['requester']['acc'], config['requester']['region'],
                         config['accepter']['acc'], config['accepter']['region'])
            app.log.warn("Existing route tables will be updated as:")
            app.log.warn("At requester side, route table->accepter subnets: %s",
                         json.dumps(config['desired']['requester'], indent=2, default=str))
            app.log.warn("At accepter side, route table->requester subnets: %s",
                         json.dumps(config['desired']['accepter'], indent=2, default=str))


def create_peering(logger, config):
    """
    setup peering only.
    """
    logger.warn("Peering from requester(%s) to accepter(%s)", config['requester']['acc'], config['accepter']['acc'])
    local_vpc_id = config['requester']['vpc_resource'].id
    peer_vpc_id = config['accepter']['vpc_resource'].id
    peer_owner_id = config['accepter']['acc']
    peer_region = config['accepter']['region']
    logger.warn("Requesting from requester(%s) side.", config['requester']['acc'])
    peering_id = config['requester']['ec2_client']. \
        create_vpc_peering_connection(
        VpcId=local_vpc_id,
        PeerVpcId=peer_vpc_id,
        PeerOwnerId=peer_owner_id,
        PeerRegion=peer_region
    )['VpcPeeringConnection']['VpcPeeringConnectionId']
    config['peering_connection_id'] = peering_id
    logger.warn("Approving from accepter(%s) side for peering %s.", config['accepter']['acc'], peering_id)
    retry_count = 20
    while True:
        try:
            config['accepter']['ec2_client'].accept_vpc_peering_connection(
                VpcPeeringConnectionId=peering_id
            )
            break
        except Exception as exc:
            if 'InvalidVpcPeeringConnectionID.NotFound' in exc.message:
                logger.debug("The acceptor does not know the peering Id yet. wait.")
                sleep(10)
                if retry_count <= 0:
                    logger.error("Retried %d times and the accepter(%s) still does not know about"
                                 " the vpc peering id %s. Something is wrong.",
                                 config['accepter']['acc'], peering_id)
                    exit(1)
                retry_count -= 1
            else:
                logger.error("Exception happened during accepting %s : %s", peering_id, exc)
                exit(1)

    logger.warn("Peering accepted, setting up routing.")

    for party, setup in config['desired'].items():
        for route_table, target_subnets in setup.items():
            for target_subnet in target_subnets:
                logger.warn("Add routing item in %s for cidr %s, destination %s",
                            route_table, target_subnet.cidr_block, config['peering_connection_id'])
                response = config[party]['ec2_client'].create_route(
                    RouteTableId=route_table,
                    DestinationCidrBlock=target_subnet.cidr_block,
                    VpcPeeringConnectionId=config['peering_connection_id']
                )
                if not response:
                    logger.error("Failed to update route table '%s' with destination cidr '%s'",
                                 route_table, target_subnet.cidr_block)
                    exit(1)

    logger.warn("DONE.")


def beautify_routes_dest(route):
    return ":".join(filter(lambda x: x is not None,
                           (
                               route.vpc_peering_connection_id,
                               route.egress_only_internet_gateway_id,
                               route.gateway_id,
                               route.instance_id,
                               route.nat_gateway_id,
                               route.network_interface_id,
                           )))


def cleanup_peering(logger, config):
    """
    Clean up peering and routes.
    """
    # cleanup vpc peer for parties
    logger.warn("Cleaning up existing peers.")
    for party in ['requester', 'accepter']:
        for peer in config[party]['existing_peer']:
            logger.warn('Tear down peering: %s %s', config[party]['vpc_name'], peer.id)
            try:
                peer.delete()
                while True:  # wait for status in deleted
                    try:
                        resp = config[party]['ec2_client'].describe_vpc_peering_connections(
                            VpcPeeringConnectionIds=[peer.id]
                        )
                        if resp['VpcPeeringConnections']['Status']['Code'] == 'deleted':
                            break
                        sleep(10)
                    except Exception:
                        break  # if no longer accessible, then still OK to proceed.
            except Exception as exc:
                if 'InvalidStateTransition' in exc.message:
                    logger.info("Exception happens, cannot delete the VPC peering as its state is be right."
                                "This error can be ignored. ")

            for route_table in config[party]['vpc_resource'].route_tables.all():
                for item in route_table.routes:
                    if item.vpc_peering_connection_id is None:  # nothing related to peering.
                        continue
                    if item.vpc_peering_connection_id == peer.id \
                            or item.vpc_peering_connection_id.startswith(
                                'pcx-') and item.state == 'blackhole':  # here we also clean up
                        # possible garbages due to previous vpc peering failure, so in the future
                        # there are less possibility in conflicts
                        logger.warn('delete item in route: %s, destination %s, cidr %s, state: %s',
                                    item.route_table_id, item.vpc_peering_connection_id,
                                    item.destination_cidr_block, item.state)
                        try:
                            item.delete()
                        except:  # try delete, regardless of error.
                            pass
    logger.info("DONE.")


def analyse_route_config(logger, config):
    """
    Find out what are the desired routetable->subnet mappings
    """
    logger.info("Validating network configuration...")
    config['desired'] = {}
    route_destination_conflicted = []
    # populate the original config with actual resources with ids.
    for party_from, party_to in [('requester', 'accepter'), ('accepter', 'requester')]:
        routes_config = config['routes'].get(party_from)
        if not routes_config:
            continue
        routes_config = {}
        config['desired'].update({party_from: routes_config})
        for item in config['routes'][party_from]:
            all_route_tables = list(config[party_from]['vpc_resource'].route_tables.all())
            all_dest_subnets = list(config[party_to]['vpc_resource'].subnets.all())
            affected_route_tables = filter_by_id_or_prefix(logger,
                                                           all_route_tables,
                                                           item['route_table'],
                                                           config[party_from]['vpc_name'])

            if not affected_route_tables:
                logger.error("Could not find route table looks like '%s' for '%s'",
                             item['route_table'], party_from)
                exit(1)
            affected_subnets = filter_by_id_or_prefix(logger,
                                                      all_dest_subnets,
                                                      item['to'],
                                                      config[party_to]['vpc_name'])
            if not affected_subnets:
                logger.error("Could not find route table looks like '%s' for '%s'",
                             item['to'], party_to)
                exit(1)
            # collect cidr information
            affected_cidrs = [s.cidr_block for s in affected_subnets]
            to_be_removed_peer_ids = [p.id for p in config[party_from]['all_existing_peers']]

            route_destination_non_related = [
                [(
                    r.destination_cidr_block,
                    rt.id,
                    beautify_routes_dest(r),
                    config[party_from]['acc'],
                    rt.vpc_id
                )
                    for r in rt.routes
                    if r.vpc_peering_connection_id is None  # crap, it is for other non-vpc, will keep
                       or r.vpc_peering_connection_id not in to_be_removed_peer_ids and r.state != 'blackhole'
                    # it is still being consumed by an active vpc peering
                ]
                for rt in affected_route_tables]
            # flatten route_destination_non_related
            route_destination_non_related = reduce(lambda x, y: x + y, route_destination_non_related)
            # filter these are in the affected_cidrs
            route_destination_conflicted += filter(lambda x: x[0] in affected_cidrs, route_destination_non_related)
            for from_route_table in affected_route_tables:
                if not routes_config.get(from_route_table.id):
                    routes_config[from_route_table.id] = []
                for to_subnet in affected_subnets:
                    routes_config[from_route_table.id].append(to_subnet)
    if route_destination_conflicted:
        for conflict in route_destination_conflicted:
            logger.error(
                "Potential future cidr conflicts in routing. cidr: %s, route_table id %s, currently being used by %s. "
                "Login AWS console for User: %s, VPC: %s to resolve it, then come back and re-run this tool.",
                conflict[0], conflict[1], conflict[2], conflict[3], conflict[4])
        exit(1)
    logger.info("DONE.")


# pylint: disable=too-many-branches
def verify_vpcs(logger, config, root_profile=None, region='ap-southeast-2'):
    """
    Verify if the config's vpc configuration allows carrying out the next operations.
    If permission does not exist, or cannot identify the only one VPC to operate on both requester and
    accepter VPC, an exception is raised.

    If current configuration conflicts with operation mode, then raise Exception.
    Mode: careful: if existing vpc has peering, then do nothing.
          modest: only create or upgrade from existing peering between the two vpcs. Else exit. (default)
          force: clean whatever peering of both VPCs setting and build peering.

    As a result, the config will be updated.
    """
    logger.info("Verify VPC information...")
    boto_session = boto3.Session(profile_name=root_profile)
    # current only support assume role. extend them in the future
    for party in ['requester', 'accepter']:
        logger.info('Analysing %s' % party)
        if config[party].get('credential') and config[party].get('credential').get('role'):
            role = config[party].get('credential').get('role')
            logger.info("Assuming to role: %s", role)
            assumedRoleObject = boto_session.client('sts').assume_role(
                RoleArn=role,
                RoleSessionName="peering")
            ec2_resource = boto3.resource('ec2',
                                          aws_access_key_id=assumedRoleObject['Credentials']['AccessKeyId'],
                                          aws_secret_access_key=assumedRoleObject['Credentials']['SecretAccessKey'],
                                          aws_session_token=assumedRoleObject['Credentials']['SessionToken'],
                                          region_name=config[party].get('region', region))
            ec2_client = boto3.client('ec2',
                                      aws_access_key_id=assumedRoleObject['Credentials']['AccessKeyId'],
                                      aws_secret_access_key=assumedRoleObject['Credentials']['SecretAccessKey'],
                                      aws_session_token=assumedRoleObject['Credentials']['SessionToken'],
                                      region_name=config[party].get('region', region))
        else:
            ec2_resource = boto_session.resource('ec2', region_name=config[party].get('region', region))
            ec2_client = boto_session.client('ec2', region_name=config[party].get('region', region))
        found_vpcs = filter_by_id_or_prefix(logger, ec2_resource.vpcs.all(), config[party].get('vpc'), None)
        if not found_vpcs:
            logger.error("Failed to locate an VPC with id or Name like '%s'", config[party].get('vpc'))
            exit(1)
        if len(found_vpcs) > 1:
            logger.error("Failed. Multiple VPC with id or Name like '%s'", config[party].get('vpc'))
            exit(1)
        config[party]['ec2_resource'] = ec2_resource
        config[party]['ec2_client'] = ec2_client
        config[party]['vpc_resource'] = found_vpcs[0]
        if config[party]['vpc_resource'].tags:
            for tag in config[party]['vpc_resource'].tags:
                if tag['Key'] == 'Name':
                    config[party]['vpc_name'] = tag['Value']
                    break
        if 'vpc_name' not in config[party]:
            logger.error("The vpc '%s' does not have Name tag, which is required!", found_vpcs[0].id)
            exit(1)
        config[party]['all_existing_peers'] = get_peers(found_vpcs[0])

    logger.info("DONE.")
    return config


def config_gen(logger):
    logger.info("Entering the interactive mode of generating vpc peering config. If you type something "
                "wrong during the process, you are OK to continue. You can always come back and edit the "
                "generated configuration content.")
    print ("Collecting the the account and VPC info ----------------------------")
    requester_acc = input(
        "Which account initiates the vpc_peering requests, aka. the requester. (For Rozetta shared service "
        "setup, it is ideal to use sysadmin(790966503942) account)."
        "Example 790966503942):")
    print ("Collecting the the account and VPC info ----------------------------")
    requester_vpc = input("Which vpc to peer on the requester side (For rozetta shared service in sydney"
                              "Region, it is OFFVPC-Sydney). This can be in VPC name or vpc-id. "
                              "Example OFFVPC-Sydney):")
    requester_role = input("Which aws role to use for requester. If empty, then the script will"
                               "use the profile in parameter. Example: crossacc_dev1):")
    requester_region = input("Which aws profile to use for requester. If not provided, then default to "
                                 "ap-southest-2. Example: ap-southest-2):")

    accepter_acc = input("Which account accepts the vpc_peering request, aka. the accepter. "
                             "Example 12345678012):")
    accepter_vpc = input("Which vpc to peer on the accepter side. This can be VPC name or vpc-id. "
                             "Example rap-prod2-ap-southeast-2):")
    accepter_role = input("Which aws profile to use for accepter. If not provided, then the script will"
                              "use the profile in parameter. Example: crossacc_dev1):")
    accepter_region = input("Which aws profile to use for accepter. If not provided, then default to "
                                "ap-southest-2. Example: ap-southest-2):")
    config = {
        'requester': {
            'acc': requester_acc,
            'vpc': requester_vpc,
            'region': requester_region if requester_region else 'ap-southeast-2'
        },
        'accepter': {
            'acc': accepter_acc,
            'vpc': accepter_vpc,
            'region': accepter_role if accepter_region else 'ap-southeast-2'
        },
    }
    if requester_role:
        if not requester_role.startswith('arn'):
            requester_role = 'arn:aws:iam::{acc}:role/{role}'.format(role=requester_role, acc=requester_acc)
        config['accepter']['credential'] = {
            'role': requester_role
        }
    if accepter_role:
        if not accepter_role.startswith('arn'):
            accepter_role = 'arn:aws:iam::{acc}:role/{role}'.format(role=accepter_role, acc=accepter_acc)
        config['requester']['credential'] = {
            'role': accepter_role
        }

    routes_setting = {}
    for side, peer in (('requester', 'accepter'), ('accepter', 'requester')):
        print ("Collecting the the routes info for %s side ----------------------------" % side)
        while True:
            from_route = input("Which route table to update on %s side. "
                                   "(can be the name prefix, which can match multiple route tables, press"
                                   "enter to finish): " % side)
            if from_route == '':
                break

            to_route = input("   :: For %s, it routs to which subnet(s) on %s side? "
                                 "(can be the name prefix. If input empty, then it matches ALL subnets): "
                                 % (from_route, peer))
            if side in routes_setting:
                routes_setting[side].append(
                    {
                        'route_table': from_route,
                        'to': to_route
                    }
                )
            else:
                routes_setting[side] = [{
                    'route_table': from_route,
                    'to': to_route
                }]
    if routes_setting:
        config['routes'] = routes_setting
    print ('======================== CONFIG STARTS ========================')
    print (yaml.dump(config, default_flow_style=False))
    print ('======================== CONFIG ENDS ========================')
    print ('You can copy and modify the above yaml file into a config file and run this tool again. ')


vpc_peering.add_param('-c', '--config',
                      help='OPTIONAL. Configuration file. If not provided, then this app ignores other'
                           'parameters and simply generate a skeleton of config file.')
vpc_peering.add_param('-f', '--force', default=False, action='store_true',
                      help='OPTIONAL. If force is not enabled, then when there are existing '
                           'peering exists, regardless if they are active, then delete them and then'
                           're-configure with the template definition. ')
vpc_peering.add_param('-a', '--action', choices=['apply', 'delete', 'plan'], required=False, default='apply',
                      help='OPTIONAL. apply: Create or update peering setting to desired configuration.'
                           'delete: Delete the peering between two VPCs.')
vpc_peering.add_param("-r", "--region", help="region to override the settings in profile", default='ap-southeast-2')
vpc_peering.add_param("-p", "--profile", help="the default profile if not specified in the config", default=None)

if __name__ == "__main__":
    vpc_peering.run()

def main():
    vpc_peering.run()
    return 0
