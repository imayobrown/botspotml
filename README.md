# 2019-Spring-CSE6242-mlserver

## Non-API

### Homepage

**URL**: `/`

Links out to the commonly used pages. Future plans are for this page to contain the API documentation.

### Upload

**URL**: `/v1/upload`

Though the endpoint has the `/v1` prefix, it is not yet part of the official API. Currently, uploads are only supported via an html form. Future plans are to streamline this via API and document how to use it.

## API

### Processing

**URL**: `/v1/processing`

**Method**: `GET`

List the uploaded `.pcap` files that are being processed by the server at the time of the request.

### List

#### unclassified

**URL**: `/v1/list/csv/unclassified`

**Method**: `GET`

List the raw unclassified flow csv files (the flow files produced before they are processed and classified by models).

#### classified

**URL**: `/v1/list/csv/classified/<model_type>`

**Method**: `GET`

Valid values for `model_type`: [`rfc`, `dnn`]

List the csv flow files after they have been classified by a model of type `model_type`

### CSV

#### unclassified

**URL:** `/v1/csv/unclassified/<file_name>`

**Method**: `GET`

__query parameters__:

* `columns`: Filter results down to specified columns using comma separated list of column names. **NOTE:** Column names must be url encoded.

Download a raw csv flow file with `file_name` from the server. Used to retrieve raw results of extracting flows from `.pcap` files.

#### classified

**URL**: `/v1/csv/classified/<model_type>/<file_name>`

Valid values for `model_type`: [`rfc`, `dnn`]

__query parameters__:

* `columns`: Filter results down to specified columns using comma separated list of column names. **NOTE:** Column names must be url encoded.

Download a file flow file which has been processed and classified by a model of type `model_type`.
