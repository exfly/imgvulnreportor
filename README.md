# imgvulnreportor
img vuln reportor


## usage

```
mkdir bin
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ./bin

export PATH="$PATH:./bin"
pipenv install --dev -v
python main.py
```
