import os
import pickle

import numpy as np
import pandas as pd

from multiprocessing import Process
from subprocess import call


DIR_FLOW_LOG           = 'flow_creation_logs'
DIR_FLOW_PROCESS       = 'flow_process_semaphores'
DIR_CSV                = 'csv'
DIR_MODELS             = 'models'
DIR_CLASSIFIED_FLOWS   = os.path.join(DIR_CSV, 'classified_flows')
DIR_UNCLASSIFIED_FLOWS = os.path.join(DIR_CSV, 'unclassified_flows')


def rfc_classification(data, pcap_file_name):
    """
    Args:
        data: pd.DataFrame
    """

    print('Binning data for Random Forest Classifier...')

    bins = 5

    # binning columns
    for feature in data.columns[7:]:

        print('Feature: ', feature)

        data[feature] = pd.cut(data[feature], bins, labels=False)

    data_model = data[['Src Port', 'Dst Port', 'Protocol',
       'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
       'Total Sum Bytes', 'Max / Avg', 'Total Packets']]

    data_model_ndarray = data_model.values

    # Unpickle rfc model and classify data

    with open('./{}/rfc_model.pkl'.format(DIR_MODELS), 'rb') as rfc_pkl:

        rfc_model = pickle.load(rfc_pkl)

    print('Classifying data using Random Forest model...')

    labels = rfc_model.predict(data_model_ndarray)

    data['Label'] = labels

    # Write out classified data to csv file

    labeled_flow_csv_path = '{}/{}_Flow_labeled.csv'.format(DIR_CLASSIFIED_FLOWS, pcap_file_name)

    print('Writing data classified by Random Forest model to {}...'.format(labeled_flow_csv_path))

    # print('Data: ', data)

    data.to_csv(labeled_flow_csv_path)


def clean_data_and_add_composite_features(pcap_file_name):
    """
    Args:
        pcap_file_name: str

    return:
        pcap_flow: pd.DataFrame
    """

    print('Cleaning data and adding composite features to generated flows...')

    # Read data in pandas DataFrame

    pcap_flow = pd.read_csv(os.path.join(DIR_UNCLASSIFIED_FLOWS, '{}_Flow.csv'.format(pcap_file_name)), low_memory=False)

    # Create composite features

    pcap_flow['Total Sum Bytes'] = pd.Series(np.sum([pcap_flow['TotLen Fwd Pkts'], pcap_flow['TotLen Bwd Pkts']], axis=0))
    pcap_flow['Max / Avg'] = pd.Series(np.divide(pcap_flow['Pkt Len Max'], pcap_flow['Pkt Len Mean']))
    pcap_flow['Total Packets'] = pd.Series(np.sum([pcap_flow['Tot Fwd Pkts'], pcap_flow['Tot Bwd Pkts']], axis=0))

    # Pop off the label columm

    pcap_flow.pop('Label')

    # Clean the data

    pcap_flow = pcap_flow.fillna(0)  # Replace NaN's with 0's

    feature_list = [ col for col in pcap_flow.columns ]

    for feature in feature_list[7:-3]:

        pcap_flow[feature] = pcap_flow[feature].replace('E', '', regex=True).replace('-', '', regex=True).replace('Infinity', '0', regex=True).astype(float)

    return pcap_flow


def generate_flows_with_cic_flow_meter(pcap_file_name):
    """
    Args:
        pcap_file_name: str
    """

    env = {
        'PATH': os.environ['PATH'],
        'JAVA_OPTS': '-Xmx4g -Xms2g'
    }

    semaphore_file = '{}/{}.processing'.format(DIR_FLOW_PROCESS, pcap_file_name)

    with open(semaphore_file, 'wb'): pass

    with open('{}/{}.log'.format(DIR_FLOW_LOG, pcap_file_name), 'wb') as log:

        call(['./cfm', '../../pcap/{}'.format(pcap_file_name), '../../{}'.format(DIR_UNCLASSIFIED_FLOWS)], stdout=log, stderr=log, env=env, cwd='./CICFlowMeter-4.0/bin/')

    os.remove(semaphore_file)


def process_pcap(pcap_file_name):
    """
    Args:
        pcap_file_name: str
    """

    # generate_flows_with_cic_flow_meter(pcap_file_name)

    cleaned_data = clean_data_and_add_composite_features(pcap_file_name)

    rfc_classification(cleaned_data.copy(), pcap_file_name)


def process_pcap_async(pcap_filename):
    """
    Args:
        pcap_file_name: str
    """

    async_process = Process(name='process-{}'.format(pcap_filename), target=process_pcap, args=(pcap_filename,))

    async_process.start()


if __name__ == '__main__':

    process_pcap_async('testDset-with-iscx.pcap')
