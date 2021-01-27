# aws-ssh

A pure-python implementation of Amazon's Session Manager Client. It performs lookups for instance names and transforms them to an instance ID needed for starting a sestion. To do this, it reads the instance's `Name` tag.

## Usage:
```bash
python main.py example-instance-name
python main.py i-fakeinstanceid023994
```
