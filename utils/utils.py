import os

from multiprocessing import Process
from subprocess import call


DIR_FLOW_LOG     = 'flow_creation_logs'
DIR_FLOW_PROCESS = 'flow_process_semaphores'


def process_pcap(pcap_file_name):

    env = {
        'PATH': os.environ['PATH'],
        'JAVA_OPTS': '-Xmx4g -Xms2g'
    }

    semaphore_file = '{}/{}.processing'.format(DIR_FLOW_PROCESS, pcap_file_name)

    with open(semaphore_file, 'wb'): pass

    with open('{}/{}.log'.format(DIR_FLOW_LOG, pcap_file_name), 'wb') as log:

        call(['./cfm', '../../pcap/{}'.format(pcap_file_name), '../../csv/'], stdout=log, stderr=log, env=env, cwd='./CICFlowMeter-4.0/bin/')

    os.remove(semaphore_file)


def process_pcap_async(pcap_filename):

    async_process = Process(name='process-{}'.format(pcap_filename), target=process_pcap, args=(pcap_filename,))

    async_process.start()


if __name__ == '__main__':

    process_pcap_async('testDset-with_iscx.pcap')
