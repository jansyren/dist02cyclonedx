This is a pretty much a translation of the python tool distro2sbom and lib4sbom by anthonyharrison. We just wanted to be able to have a binary that could easily be distributed to systems instead of having to setup a python environment.

It is still a work in progress and some functionality is missing, it will only output cyclonedx 1.6, and it only works on Linux distributions. At the time of writing only Ubuntu is tested but the application is prepared for deb, apk or rpm based operating systems.

To run it you simply run dist02cyclonedx --distro <distro> -o sbom.json
Currently it requires a copy of https://cyclonedx.org/schema/spdx.schema.json by the executeable, I will make this an argument later on.

The output has been tested to upload to dependencytrack and so far so good.

---

**Command line arguments** </br>
`--distro <distro>` *the name of the distribution in small letters* </br>
`-o <path/file>` *the path to the output file and name of the output file </br>
`--api-url <URL>` *the API url of dependencytrack* </br>
`--api-key <key>` *the api key to use for the API* </br>
`tls-verify true|false` *default **true**, if tls should verify the certificate of dependencytrack* </br>

---
</br>

**Configuration file** </br>
</br>
The configuration file is hardcoded to /etc/dist02cyclonedx.yaml </br>

Content of the configuration file can be:

    distro: ubuntu
    output: /tmp/sbom.json
    api-url: https://url
    api-key: jsdklfjweuehfskjdhfjk
    tls-verify: true

</br>
---

**Fixes**

* ~~Ensure all distributions are working - Ubuntu and Rocky tested~~
* ~~Add automatic upload to dependencytrack - Working~~
* ~~Add a config file~~
* Run differential on packages and update existing sbom
