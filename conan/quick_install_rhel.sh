#!/usr/bin/env sh
sudo adduser opentlc-mgr

sudo dnf install -y vim git wget rush kerberos krb5-workstation ipa-client python3-pip

sudo -u opentlc-mgr mkdir -p -m 700 \
    ~opentlc-mgr/.aws/ \
    ~opentlc-mgr/secrets \
    ~opentlc-mgr/pool_management/output_dir_sandbox

cd /tmp

wget https://github.com/rebuy-de/aws-nuke/releases/download/v2.19.0/aws-nuke-v2.19.0-linux-amd64.tar.gz
wget https://github.com/shenwei356/rush/releases/download/v0.5.0/rush_linux_amd64.tar.gz

tar xzvf aws-nuke-v2.19.0-linux-amd64.tar.gz
tar xzvf rush_linux_amd64.tar.gz

mv aws-nuke-v2.19.0-linux-amd64 /usr/bin/
ln -s /usr/bin/aws-nuke-v2.19.0-linux-amd64 /usr/bin/aws-nuke
mv rush /usr/bin/

sudo -u opentlc-mgr git clone https://github.com/rhpds/sandbox.git ~opentlc-mgr/pool_management/sandbox
# Create symlink to sandbox (compatibility with old scripts)
sudo -u opentlc-mgr ln -s ~opentlc-mgr/pool_management/sandbox/ ~opentlc-mgr/pool_management/aws-sandbox

echo "Edit ~opentlc-mgr/.aws/credentials"
echo "Setup IPA access (ipa-client-install)"
echo "copy secret: hostadmin.keytab into ~opentlc-mgr/secrets/"
echo "copy secret: infra-sandbox-vault into ~opentlc-mgr/secrets/"

sudo cp ~opentlc-mgr/pool_management/sandbox/conan/conan.service /etc/systemd/system/
sudo systemctl daemon-reload
