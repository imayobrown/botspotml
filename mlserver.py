import os

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
from utils.utils import DIR_CLASSIFIED_FLOWS
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

    if not os.path.exists(DIR_CLASSIFIED_FLOWS):

        os.makedirs(DIR_CLASSIFIED_FLOWS)

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


@app.route('/v1/csv/<file_name>')
def send_csv_file(file_name):

    # return send_file(os.path.join(app.config['UPLOADS_DEFAULT_DEST'], 'ISCX_Botnet-Training.pcap_Flow.csv'))
    return send_file(os.path.join(app.config['UPLOADS_DEFAULT_DEST'], file_name))


@app.route('/v1/list/<file_type>')
def list_files(file_type):

    files = os.listdir(os.path.join(app.config['UPLOADS_DEFAULT_DEST'], secure_filename(file_type)))

    response = {
        'Results': files
    }

    # response = render_template('list.html', file_type=file_type, files=files)

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

    # response = '\n'.join(pcaps_being_processed)

    return jsonify(response)
