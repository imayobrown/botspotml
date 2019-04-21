import os
import tempfile

import pandas as pd

from flask import abort
from flask import flash
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import url_for
from flask_uploads import configure_uploads
from flask_uploads import UploadSet
from werkzeug.utils import secure_filename

from utils.utils import process_pcap_async
from utils.utils import DIR_FLOW_LOG
from utils.utils import DIR_FLOW_PROCESS
from utils.utils import DIR_CLASSIFIED_FLOWS_RFC
from utils.utils import DIR_CLASSIFIED_FLOWS_DNN
from utils.utils import DIR_UNCLASSIFIED_FLOWS


pcap = UploadSet('pcap', extensions=('pcap'))

app = Flask(__name__)

app.secret_key = b'testsecretkey'

app.config['UPLOADS_DEFAULT_DEST'] = os.getcwd()

configure_uploads(app, (pcap))


# HELPER FUNCTIONS

def create_flow_log_dirs():

    if not os.path.exists(DIR_FLOW_LOG):

        os.makedirs(DIR_FLOW_LOG)

    if not os.path.exists(DIR_FLOW_PROCESS):

        os.makedirs(DIR_FLOW_PROCESS)


def create_csv_flow_dirs():

    if not os.path.exists(DIR_CLASSIFIED_FLOWS_RFC):

        os.makedirs(DIR_CLASSIFIED_FLOWS_RFC)

    if not os.path.exists(DIR_CLASSIFIED_FLOWS_DNN):

        os.makedirs(DIR_CLASSIFIED_FLOWS_DNN)

    if not os.path.exists(DIR_UNCLASSIFIED_FLOWS):

        os.makedirs(DIR_UNCLASSIFIED_FLOWS)


@app.before_first_request
def init():

    create_flow_log_dirs()

    create_csv_flow_dirs()


# ENDPOINTS

@app.route('/')
def home():

    return render_template('home.html')


@app.route('/v1/csv/unclassified/<file_name>')
def send_unclassified_csv_file(file_name):

    columns = request.args.get('columns').split(',') if 'columns' in request.args else []

    csv_file_path = os.path.join(os.getcwd(), DIR_UNCLASSIFIED_FLOWS, secure_filename(file_name))

    if len(columns) != 0:

        data_subset = pd.read_csv(csv_file_path)

        data_subset = data_subset[columns]

        with tempfile.NamedTemporaryFile() as temp_csv_file:

            data_subset.to_csv(temp_csv_file.name, index=False)

            return send_file(temp_csv_file.name)

    else:

        return send_file(os.path.join(os.getcwd(), DIR_UNCLASSIFIED_FLOWS, secure_filename(file_name)))


@app.route('/v1/csv/classified/<model_type>/<file_name>')
def send_classified_csv_file(model_type, file_name):

    if model_type in ['rfc', 'dnn']:

        if model_type == 'rfc':

            target_directory = DIR_CLASSIFIED_FLOWS_RFC

        if model_type == 'dnn':

            target_directory = DIR_CLASSIFIED_FLOWS_DNN

        columns = request.args.get('columns').split(',') if 'columns' in request.args else []

        csv_file_path = os.path.join(os.getcwd(), target_directory, secure_filename(file_name))

        if len(columns) != 0:

            data_subset = pd.read_csv(csv_file_path)

            data_subset = data_subset[columns]

            with tempfile.NamedTemporaryFile() as temp_csv_file:

                data_subset.to_csv(temp_csv_file.name, index=False)

                return send_file(temp_csv_file.name)

        else:

            return send_file(os.path.join(os.getcwd(), target_directory, secure_filename(file_name)))

    else:

        return "Classifier of type '{}' is not yet supported.".format(model_type), 404


@app.route('/v1/list/csv/unclassified')
def list_unclassified_flow_files():

    files = os.listdir(os.path.join(os.getcwd(), DIR_UNCLASSIFIED_FLOWS))

    response = {
        'Results': files
    }

    return jsonify(response)


@app.route('/v1/list/csv/classified/<model_type>')
def list_classified_flow_files(model_type):

    if model_type not in ['rfc', 'dnn']:

        error_json = {
            'Results': None,
            'Error': "Valid values for /v1/csv/classified/<model_type> are ['rfc', 'dnn']"
        }

        return jsonify(error_json), 404

    if model_type == 'rfc':

        target_directory = DIR_CLASSIFIED_FLOWS_RFC

    if model_type == 'dnn':

        target_directory = DIR_CLASSIFIED_FLOWS_DNN

    files = os.listdir(os.path.join(os.getcwd(), target_directory))

    response = {
        'Results': files
    }

    return jsonify(response)


@app.route('/v1/upload', methods=['GET', 'POST'])
def upload():

    if request.method == 'POST' and 'pcap' in request.files:

        filename = pcap.save(request.files['pcap'])

        process_pcap_async(filename)

        return redirect(url_for('upload_success'))

    return render_template('upload.html')


@app.route('/v1/upload_success')
def upload_success():

    return 'FILE SAVED!'


@app.route('/v1/processing')
def processing():

    pcaps_in_progress = os.listdir(DIR_FLOW_PROCESS)

    mapped_pcaps = [ x[:-11] for x in pcaps_in_progress]

    response = {
        'Results': mapped_pcaps
    }

    return jsonify(response)


if __name__ == '__main__':

    app.run(host='0.0.0.0', debug=True)
