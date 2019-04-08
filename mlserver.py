import os

from multiprocessing.pool import Pool
from multiprocessing import Queue

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

from utils.utils import process_pcap
from utils.utils import process_echo


CONTENT_TYPE = 'Content-Type'


pcap = UploadSet('pcap', extensions=('pcap'))

app = Flask(__name__)

app.secret_key = b'testsecretkey'

app.config['UPLOADS_DEFAULT_DEST'] = os.getcwd()

configure_uploads(app, (pcap))

process_pool = Pool(4)

in_process_queue = Queue(20)


# HELPER FUNCTIONS

def submit_process(func, args):

    global process_pool

    res = process_pool.apply_async(func, args)

    return res


def submit_echo_process():

    echo_arg = "ECHO THIS"

    res = submit_process(process_echo, (echo_arg, app.logger))

    return res


def submit_pcap_process(pcap_file_name):

    res = submit_process(process_pcap, (pcap_file_name))

    return res


# ENDPOINTS

@app.route('/')
def home():

    return render_template('home.html')


@app.route('/v1/echo')
def echo():

    submit_echo_process()

    return 'echo'


@app.route('/v1/process/pcap/<file_name>')
def process_pcap(file_name):

    res = submit_pcap_process(file_name)

    app.logger.info(res.get(timeout=1))

    return 'Processing...'


@app.route('/v1/csv/test')
def send_csv_file():

    return send_file(os.path.join(app.config['UPLOADS_DEFAULT_DEST'], 'ISCX_Botnet-Training.pcap_Flow.csv'))


@app.route('/v1/list/<file_type>')
def list_files(file_type):

    files = os.listdir(os.path.join(app.config['UPLOADS_DEFAULT_DEST'], secure_filename(file_type)))

    if CONTENT_TYPE in request.headers and request.headers[CONTENT_TYPE] == 'application/json':

        response = jsonify(files)

    else:

        response = render_template('list.html', file_type=file_type, files=files)

    return response


@app.route('/v1/upload', methods=['GET', 'POST'])
def upload():

    if request.method == 'POST' and 'pcap' in request.files:

        filename = pcap.save(request.files['pcap'])

        submit_pcap_process(filename)

        return redirect(url_for('upload_success'))

    return render_template('upload.html')


@app.route('/v1/upload_success')
def upload_success():

    return 'FILE SAVED!'


@app.route('/v1/processing')
def processing():

    return 'LIST OF THINGS BEING PROCESSED...'
