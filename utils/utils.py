from subprocess import call


def process_pcap(pcap_file_name):

    call(['./cfm', '../../pcap/{}'.format(pcap_file_name), '../../csv/'], cwd='./CICFlowMeter-4.0/bin/')


def process_echo(thing_to_echo, logger):

    logger.info('Performing echo with {}'.format(thing_to_echo))

    call(['echo', '{}'.format(thing_to_echo)])
