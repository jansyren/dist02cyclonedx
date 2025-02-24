This is a pretty much a translation of the python tool distro2sbom and lib4sbom by anthonyharrison. We just wanted to be able to have a binary that could easily be distributed to systems instead of having to setup a python environment.

It is still a work in progress and some functionality is missing, it will only output cyclonedx 1.6, and it only works on Linux distributions. At the time of writing only Ubuntu is tested but the application is prepared for deb, apk or rpm based operating systems.

To run it you simply run dist02cyclonedx --distro <distro> -o sbom.json
Currently it requires a copy of https://cyclonedx.org/schema/spdx.schema.json by the executeable, I will make this an argument later on.

The output has been tested to upload to dependencytrack and so far so good.

Fixes

Ensure all distributions are working
Add automatic upload to dependencytrack
Add a config file
Run differential on packages and update existing sbom
