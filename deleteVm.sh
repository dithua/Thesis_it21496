VMNAME=$(hostname)
ZONE=$(curl -H Metadata-Flavor:Google http://metadata/computeMetadata/v1/instance/zone | cut -d/ -f4)
sudo gcloud compute instances delete $VMNAME --zone $ZONE --quiet
