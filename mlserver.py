from flask import Flask

app = Flask(__name__)

@app.route('/v1/ip/<source_ip>/<destination_ip>')
def information_ip_pair(source_ip, destination_ip):

    return "Currently Under Construction..."


@app.route('/v1/port/<source_port>/<destination_port>')
def information_port_pair(source_port, destination_port):

    return "Currently Under Construction..."
