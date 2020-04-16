# Assemblyline 4 

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


