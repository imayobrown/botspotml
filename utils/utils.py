import os
import pickle

import numpy as np
import pandas as pd
import torch
import torch.utils.data
import torch.nn as nn

from multiprocessing import Process
from subprocess import call


DIR_FLOW_LOG             = 'flow_creation_logs'
DIR_FLOW_PROCESS         = 'flow_process_semaphores'
DIR_CSV                  = 'csv'
DIR_MODELS               = 'models'
DIR_CLASSIFIED_FLOWS     = os.path.join(DIR_CSV, 'classified_flows')
DIR_CLASSIFIED_FLOWS_RFC = os.path.join(DIR_CLASSIFIED_FLOWS, 'rfc')
DIR_CLASSIFIED_FLOWS_DNN = os.path.join(DIR_CLASSIFIED_FLOWS, 'dnn')
DIR_UNCLASSIFIED_FLOWS   = os.path.join(DIR_CSV, 'unclassified_flows')


def rfc_classification(data, pcap_file_name):
    """
    Args:
        data: pd.DataFrame
    """

    print('Binning data for Random Forest Classifier...')

    bins = 5

    # binning columns
    for feature in data.columns[7:]:

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

    labeled_flow_csv_path = '{}/{}_Flow_labeled.csv'.format(DIR_CLASSIFIED_FLOWS_RFC, pcap_file_name)

    print('Writing data classified by Random Forest model to {}...'.format(labeled_flow_csv_path))

    # print('Data: ', data)

    data.to_csv(labeled_flow_csv_path)


def dnn_predict(data, model, batch_size=200):

    # Switch to evaluate mode:
    model.eval()

    # Transform data into desired format with specified batch size:
    test_tensor = torch.utils.data.TensorDataset(torch.Tensor(data))
    test_loader = torch.utils.data.DataLoader(dataset=test_tensor, batch_size=batch_size)

    # Initiate predictions output of the function:
    predictions_output = []

    print('model: ', model)

    # Run the main testing loop:
    for batch_i, x_batch in enumerate(test_loader):

        print('x_batch: ', x_batch)

        # Predict classes of test set:
        outputs = model(x_batch[0])

        # Identify whether prediction is 0 or 1 (1 if probability is >= 0.5):
        predictions = [float(value[0]) for value in (outputs >= 0.5).tolist()]

        # Append to the output predictions:
        predictions_output.extend(predictions)

    prediction_output_labels = [ 'botnet' if x else 'notbotnet' for x in predictions_output ]

    # Format prediction output as pandas Series:
    prediction_output_labels = pd.Series(prediction_output_labels)

    return prediction_output_labels


def dnn_classification(data, pcap_file_name):

    features = ['Src Port', 'Dst Port', 'Protocol', 'Fwd Pkt Len Max',
               'Fwd Pkt Len Std', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
               'Flow IAT Max', 'Fwd IAT Max', 'Bwd IAT Tot',
               'Bwd IAT Std', 'Bwd IAT Max', 'Bwd PSH Flags', 'Fwd Pkts/s',
               'Bwd Pkts/s', 'Pkt Len Mean', 'Pkt Len Std', 'FIN Flag Cnt',
               'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio',
               'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Init Bwd Win Byts', 'Idle Mean',
               'Idle Max', 'Idle Min']

    data_model = data[features]

    data_model_ndarray = data_model.apply(pd.to_numeric).values

    # Load model from pth file

    dnn_model = Deep_Neural_Network(D_in=len(features))

    dnn_model.load_state_dict(torch.load('{}/Deep_Neural_Network.pth'.format(DIR_MODELS), map_location='cpu'), strict=False)

    dnn_model.to(torch.device('cpu'))

    labels = dnn_predict(data_model_ndarray, dnn_model)

    data['Label'] = labels

    # Write out classified data to csv file

    labeled_flow_csv_path = '{}/{}_Flow_labeled.csv'.format(DIR_CLASSIFIED_FLOWS_DNN, pcap_file_name)

    print('Writing data classified by DNN model to {}...'.format(labeled_flow_csv_path))

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

    with open('{}/{}.log'.format(DIR_FLOW_LOG, pcap_file_name), 'wb') as log:

        call(['./cfm', '../../pcap/{}'.format(pcap_file_name), '../../{}'.format(DIR_UNCLASSIFIED_FLOWS)], stdout=log, stderr=log, env=env, cwd='./CICFlowMeter-4.0/bin/')


def process_pcap(pcap_file_name):
    """
    Args:
        pcap_file_name: str
    """

    semaphore_file = '{}/{}.processing'.format(DIR_FLOW_PROCESS, pcap_file_name)

    with open(semaphore_file, 'wb'): pass

    generate_flows_with_cic_flow_meter(pcap_file_name)

    cleaned_data = clean_data_and_add_composite_features(pcap_file_name)

    rfc_classification(cleaned_data.copy(), pcap_file_name)

    dnn_classification(cleaned_data.copy(), pcap_file_name)

    os.remove(semaphore_file)


def process_pcap_async(pcap_filename):
    """
    Args:
        pcap_file_name: str
    """

    async_process = Process(name='process-{}'.format(pcap_filename), target=process_pcap, args=(pcap_filename,))

    async_process.start()


class Deep_Neural_Network(nn.Module):

    def __init__(self, D_in, fc1_size=40, fc2_size=20, fc3_size=40, fc4_size=20, fc5_size=40):
        """
        Neural Network model with 1 hidden layer.

        D_in: Dimension of input
        fc1_size, fc2_size, etc.: Dimensions of respective hidden layers
        """

        super(Deep_Neural_Network, self).__init__()

        # Input Layer:

        self.fc1 = nn.Linear(D_in, fc1_size)
        nn.init.kaiming_normal_(self.fc1.weight)
        #self.bn1 = nn.BatchNorm1d(fc1_size)
        self.relu1 = nn.LeakyReLU()

        # 2nd Layer:

        self.fc2 = nn.Linear(fc1_size, fc2_size)
        nn.init.kaiming_normal_(self.fc2.weight)
        #self.bn2 = nn.BatchNorm1d(fc2_size)
        self.relu2 = nn.LeakyReLU()

        # 3rd Layer:

        self.fc3 = nn.Linear(fc2_size, fc3_size)
        nn.init.kaiming_normal_(self.fc3.weight)
        #self.bn3 = nn.BatchNorm1d(fc3_size)
        self.relu3 = nn.LeakyReLU()

        # 4rd Layer:

        self.fc4 = nn.Linear(fc3_size, fc4_size)
        nn.init.kaiming_normal_(self.fc4.weight)
        #self.bn4 = nn.BatchNorm1d(fc4_size)
        self.relu4 = nn.LeakyReLU()

        # 5th Layer:

        self.fc5 = nn.Linear(fc4_size, fc5_size)
        nn.init.kaiming_normal_(self.fc5.weight)
        #self.bn5 = nn.BatchNorm1d(fc5_size)
        self.relu5 = nn.LeakyReLU()

        # Final Layer:

        self.fc_output = nn.Linear(fc5_size, 1) # 1 because this is binary classification
        self.fc_output_activation = nn.Sigmoid()

        # Dropout implemented across all layers except Final Layer:

        self.dropout = nn.Dropout(p=0.5)

    def forward(self, x):
        """
        Forward function acceps a Tensor of input data and returns a tensor of output data.
        """

        #out = self.dropout(self.relu1(self.bn1(self.fc1(x))))
        #out = self.dropout(self.relu2(self.bn2(self.fc2(out))))
        #out = self.dropout(self.relu3(self.bn3(self.fc3(out))))
        #out = self.dropout(self.relu4(self.bn4(self.fc4(out))))
        #out = self.dropout(self.relu5(self.bn5(self.fc5(out))))

        out = self.dropout(self.relu1(self.fc1(x)))
        out = self.dropout(self.relu2(self.fc2(out)))
        out = self.dropout(self.relu3(self.fc3(out)))
        out = self.dropout(self.relu4(self.fc4(out)))
        out = self.dropout(self.relu5(self.fc5(out)))
        out = self.fc_output_activation(self.fc_output(out))

        return out


if __name__ == '__main__':

    # process_pcap_async('testDset-with-iscx.pcap')

    pcap_file_name = 'testDset-with-iscx.pcap'

    cleaned_data = clean_data_and_add_composite_features(pcap_file_name)

    # rfc_classification(cleaned_data.copy(), pcap_file_name)

    dnn_classification(cleaned_data.copy(), pcap_file_name)
