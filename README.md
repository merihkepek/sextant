# sextant
Maps TTPs in Detection Rules to a MITRE ATT&amp;CK Navigator layer

Currently, sextant only supports [Google Chronicle SIEM](https://cloud.google.com/chronicle-siem) to automatically retrieve data from Detection Rules but in the future more systems can be supported, like EDRs.


## Usage
Before the first run, you must setup your environment and it goes just like any other Python project: Clone this repository and install the requirements (using a Virtual Environment is highly recommended).  The commands below should help:

```sh
git clone git@github.com:lopes/sextant.git
cd sextant
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run `map.py` to retrieve data from Chronicle and create the layer (use the `-h` option for a full list of arguments):

```sh
python map.py -i chronicle -a keyfile.json
```


## Name
According to [Britannica](https://www.britannica.com/technology/sextant-instrument), Sextant is an instrument for determining the angle between the horizon and a celestial body such as the Sun, the Moon, or a star, used in celestial navigation to determine latitude and longitude.

This name was chosen because in a certain way that's what this program does: Maps data from a Threat Detection tool in MITRE Navigator to help teams navigate in Infosec.  =)
