# mumble-web-proxy OCI image

This directory provides files to build a mumble-web-proxy OCI image.
The image is based on Alpine Linux and is less than 30 MiB in size.
One can use [Docker](https://www.docker.com/) in order to build the image,
as follows.

```
docker build --build-arg REV=master -t mumble-web-proxy .
```

`master` can be replaced by any revision (i.e. branch, tag or commit hash) of
this repository.
