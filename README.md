# checkpoint-remove-unused-hosts
A script for removing unused hosts in a MDS environment.

This script allows you to clean up the specified subnet by removing any unused hosts in it.

The script uses the Checkpoint Web API, which is significantly faster than the CLI command.

How it works:
1. List all domains
1. For every Domain:
    1. Login 
    1. Get all hosts and match them to the subnet
    1. Get all rules and match them to the found hosts
    1. Check if remaining host are used in any groups
    1. Remove remaining hosts
    1. Publish and log out
  
Technically you could skip step 2d since the API does not allow you to delete hosts in groups.


If you have any thougths on the script, feel free to share them with me.
