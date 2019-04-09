# 2019-Spring-CSE6242-mlserver

## Non-API

### Homepage

`/`

Links out to the commonly used pages. Future plans are for this page to contain the API documentation.

### Upload

`/v1/upload`

Though the endpoint has the `/v1` prefix, it is not yet part of the official API. Currently, uploads are only supported via an html form. Future plans are to streamline this via API and document how to use it.

## API

### Processing

`/v1/processing`

List the uploaded `.pcap` files that are being processed by the server at the time of the request.

### List

`/v1/list/<file_type>`

`file_type`: `csv`, `pcap`

List the files of `file_type` that have been uploaded to the server.

### CSV

`/v1/csv/<file_name>`

Download a csv flow file with `file_name` from the server. Used to retrieve processed `.pcap` files.
