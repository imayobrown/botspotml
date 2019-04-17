# Use the following to install PyTorch on Windows with Nvidia GPU. Link: https://pytorch.org/get-started/locally/#anaconda-1
#!pip install https://download.pytorch.org/whl/cu90/torch-1.0.1-cp37-cp37m-win_amd64.whl
#!pip install torchvision

# Load required libraries:
import pandas as pd
import numpy as np
import sklearn.model_selection
import torch
import torch.utils.data
from torch.autograd import Variable
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt
import pickle
import sys

# Load data:
pcap_flow = pd.read_csv('/home/t/PycharmProjects/Group_Project/labeled_test.csv')

# Hyperparams
batch_size = 50
epochs = 10
learning_rate = .01

# Specify labels data:
print('Storing labels and converting to numeric values')
labels = pcap_flow.pop('Label')
for x in range(len(labels)):
    if labels[x] == 'notbotnet':
        labels[x] = float(0)
    else:
        labels[x] = float(1)

labels = labels.to_numpy(dtype=float)

# Select variables:
variables = pcap_flow[['Src Port', 'Dst Port', 'Protocol',
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
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
       ]]

#  Create Synthetic Features
pcap_flow['Max / Avg'] = pd.Series(np.divide(pcap_flow['Pkt Len Max'], pcap_flow['Pkt Len Mean']))


print("Cleaning Data...")
### Clean data ###

pcap_flow = pcap_flow.fillna(0)  # Replace NaN's with 0's

feature_list = []  # List of features to iterate on

for col in pcap_flow.columns:
    feature_list.append(col)

DNN_DF_Model_Data = pcap_flow[['Src Port', 'Dst Port', 'Protocol',
       'FIN Flag Cnt', 'SYN Flag Cnt', 'ACK Flag Cnt',
       'Down/Up Ratio', 'Bwd Seg Size Avg', 'Max / Avg']].apply(pd.to_numeric).values

class Neural_Net(nn.Module):
    def __init__(self, D_in):
        """
        Neural Network model with 1 hidden layer.

        D_in: Dimension of input
        """
        super(Neural_Net, self).__init__()
        self.fc1 = nn.Linear(D_in, 100)
        self.relu1 = nn.Sigmoid()
        self.fc2 = nn.Linear(100, 50)
        self.relu2 = nn.Sigmoid()
        self.fc3 = nn.Linear(50, 20)
        self.relu3 = nn.ReLU()
        self.fc_output = nn.Linear(20, 1)
        self.fc_output_activation = nn.Sigmoid()

    def forward(self, x):
        x = self.relu1(self.fc1(x))
        x = self.relu2(self.fc2(x))
        x = self.relu3(self.fc3(x))
        x = self.fc_output_activation(self.fc_output(x))
        return x

def train_NN(data, target, batch_size, epochs, learning_rate):
    # Transform data into desired format with specified batch size:
    train_tensor = torch.utils.data.TensorDataset(torch.Tensor(data), torch.tensor(target))
    train_loader = torch.utils.data.DataLoader(dataset=train_tensor, batch_size=batch_size, shuffle=True)

    # Instantiate Neural Network:
    net = Neural_Net(data.shape[1])
    net.train()

    # Create Adam optimizer (recommended for Deep Neural Networks; betas=(0.9, 0.999) is recommended):
    optimizer = optim.Adam(net.parameters(), lr=learning_rate, betas=(0.9, 0.999))

    # Create Binary Cross Entropy loss function:
    criterion = nn.BCELoss()

    # Create total_losses list for plotting:
    total_losses = []

    # Run the main training loop
    for epoch in range(epochs):

        losses = []

        for batch_idx, (x_batch, y_batch) in enumerate(train_loader):
            x_batch, y_batch = Variable(x_batch), Variable(y_batch)

            # Zeros out all "delta" matrices before a new iteration:
            optimizer.zero_grad()

            # Forward propagation:
            net_out = net(x_batch)

            # Compute performance criterion:
            loss = criterion(net_out, y_batch.float())

            # Backward propagation:
            loss.backward()

            # Update weights:
            optimizer.step()

            # Append to total losses list:
            losses.append(loss.data.numpy())

            print('Train Epoch #{} [ {}/{} ({:.0f}%) ] Loss: {:.3f}'.format(
                epoch, batch_idx * len(x_batch), len(train_loader.dataset),
                       100.0 * batch_idx / len(train_loader), loss.data.item()))

        total_losses += losses

    return [net, total_losses]


def test(model, x_test, y_test):
    test_tensor = torch.utils.data.TensorDataset(torch.Tensor(x_test), torch.tensor(y_test))
    test_loader = torch.utils.data.DataLoader(dataset=test_tensor, batch_size=len(y_test), shuffle=True)

    dataiter = iter(test_loader)
    data, target = dataiter.next()
    model_output = model[0](data)

    _, predictions_tensor = torch.max(model_output.round(), 1)
    predictions = np.squeeze(predictions_tensor.numpy())

    metrics = sklearn.metrics.confusion_matrix(y_test, predictions).ravel()

    return metrics


x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(DNN_DF_Model_Data, labels, shuffle=True, random_state=100, test_size=0.3)

res = train_NN(data=x_train, target=y_train, batch_size=batch_size, epochs=epochs, learning_rate=learning_rate)
'''
plt.plot(res[1])
plt.xlabel("Iteration Number")
plt.ylabel("Loss")
plt.title("Neural Network: Loss per Iteration Number")
plt.show()

try:
    output = open('dnn_model.pkl', 'wb')

except IOError:
    output = open('dnn_model.pkl', 'xwb')

pickle.dump(res, output)
output.close()
'''
#  Testing
res_metrics = test(res, x_test, y_test)

print("True Negatives: {:.3%}".format(res_metrics[0] / len(y_test)))
print("True Positives: {:.3%}".format(res_metrics[3] / len(y_test)))
print("False Positives: {:.3%}".format(res_metrics[1] / len(y_test)))
print("False Negatives: {:.3%}".format(res_metrics[2] / len(y_test)))
