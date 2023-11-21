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

At this embrionic stage, using the script involves setting up the variables in `map.py` and running it.  In the future it is planned to implement a CLI to ease its usage.
