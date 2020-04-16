# Assemblyline 4 - Automated malware analysis framework

AssemblyLine 4 is an open source malware analysis framework. It leverages Kubernetes and Docker to adapt to many use cases; from a small appliance for supporting manual malware analysis and security teams to large-scale enterprise security operations scanning millions of files a day and providing triage capabilities.

AssemblyLine can be easily integrated in your environment using it’s powerful rest API and web interfaces. The platform comes with dozens of services to provide deep file analysis and enable integration with other security platforms such as anti-virus, malware-detonation sandboxes and threat knowledge bases. Best of all, with a little bit of Python code you can extend it yourself by creating new analysis and integration services.

### Repository information 

This is Assemblyline 4 base repository. It provides Assemblyline with common libraries, cachestore, datastore, filestore, ODM and remote datatypes.

#### System requirements

Assemblyline 4 will only work on systems running python3.7+ and was only tested on linux systems.   

#### Installation requirements

If used outside of our normal container this library requires outside linux libraries.
 * libffi6 (dev)
 * libfuxxy2 (dev)
 * libmagic1
 * python3.7 (dev)
 
Here is an example on how you would get those libraries on a `Ubuntu 18.04+` system:

    sudo apt install libffi6 libfuzzy2 libmagic1 build-essential libffi-dev python3.7 python3-dev python3-pip libfuzzy-dev


