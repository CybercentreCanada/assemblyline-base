[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline--base-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-base)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/base)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:base)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-base)](./LICENCE.md)

# Assemblyline 4 - Base Package

This repository provides Assemblyline with common libraries, cachestore, datastore, filestore, ODM and remote datatypes.

## Image variants and tags

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## System requirements

Assemblyline 4 will only work on systems running Python 3.11 and was only officially tested on Linux systems by the Assemblyline team.

## Installation requirements

The following Linux libraries are required for this library:

- libffi8 (dev)
- libfuxxy2 (dev)
- libmagic1
- python3.11 (dev)

Here is an example on how you would get those libraries on a `Ubuntu 20.04+` system:
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install libffi8 libfuzzy2 libmagic1 build-essential libffi-dev python3.11 python3.11-dev python3-pip libfuzzy-dev
```

**Note:** Installation of the libraries are not required if using the `cccs/assemblyline` container image

## Documentation

For more information about these Assemblyline components, follow this [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) of the system's architecture.

# Assemblage 4 - Paquet de base

Ce dépôt fournit à Assemblyline les bibliothèques communes, le cachestore, le datastore, le filestore, l'ODM et les types de données à distance.

## Variantes et étiquettes d'image

| **Type d'étiquette** | **Description**                                                                                                  |  **Exemple d'étiquette**   |
| :------------------: | :--------------------------------------------------------------------------------------------------------------- | :------------------------: |
|       dernière       | La version la plus récente (peut être instable).                                                                 |          `latest`          |
|      build_type      | Le type de compilation utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        séries        | Le détail de compilation utilisé, incluant la version et le type de compilation : `version.buildType`.           | `4.5.stable`, `4.5.1.dev3` |

## Système requis

Assemblyline 4 ne fonctionnera que sur des systèmes utilisant Python 3.11 et n'a été officiellement testé que sur des systèmes Linux par l'équipe Assemblyline.

## Configuration requise pour l'installation

Les bibliothèques Linux suivantes sont requises pour cette bibliothèque :

- libffi8 (dev)
- libfuxxy2 (dev)
- libmagic1
- python3.11 (dev)

Voici un exemple de la manière dont vous obtiendrez ces bibliothèques sur un système `Ubuntu 20.04+` :
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install libffi8 libfuzzy2 libmagic1 build-essential libffi-dev python3.11 python3.11-dev python3-pip libfuzzy-dev
```

**Note:** L'installation des bibliothèques n'est pas nécessaire si vous utilisez l'image conteneur `cccs/assemblyline`.

## Documentation

Pour plus d'informations sur ces composants Assemblyline, suivez ce [overview](https://cybercentrecanada.github.io/assemblyline4_docs/overview/architecture/) de l'architecture du système.
