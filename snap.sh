#!/bin/bash/env node
  
snapshot="ohsnap"
myProject="theses-242721"
myID=$(date +%s)
gcloud_account="702293131827-compute@developer.gserviceaccount.com"


    gcloud compute --project "${myProject}" disks create "disk${myID}" \
        --size "10" --zone "europe-west4-a" --source-snapshot "${snapshot}" \
        --type "pd-standard"

    gcloud compute --project "${myProject}" instances create "server${myID}" \
        --zone "europe-west4-a" --machine-type "f1-micro" --network "default" \
	--no-deletion-protection \
        --maintenance-policy "MIGRATE" \
        --service-account "${gcloud_account}" \
        --scopes "default","compute-rw","storage-full" \
        --tags "http-server","https-server" \
        --disk "name=disk${myID},device-name=server${myID},mode=rw,boot=yes,auto-delete=yes" \
	--metadata startup-script='#!/bin/bash -e
        forever start /home/dodina96/ChatUp/index.js'

