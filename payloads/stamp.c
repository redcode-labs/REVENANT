//Modifies access and creation times of a file
system("touch -c -d TIMESTAMP your_file.txt"); //TIMESTAMP is filled randomly by pre-processor
system("touch -ac -d TIMESTAMP your_file.txt");
//system("touch -r /etc/hostname your_file.txt");