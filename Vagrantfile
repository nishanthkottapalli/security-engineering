Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/noble64"
  config.vm.hostname = "security-capabilities-lab"
  config.vm.network "forwarded_port", guest: 8080, host: 18080, auto_correct: true
  config.vm.network "forwarded_port", guest: 8000, host: 18000, auto_correct: true

  config.vm.provider "virtualbox" do |vb|
    vb.name = "security-capabilities-lab"
    vb.memory = ENV.fetch("LAB_MEMORY_MB", "6144")
    vb.cpus = ENV.fetch("LAB_CPUS", "4")
  end

  config.vm.synced_folder ".", "/workspace", type: "virtualbox"
  config.vm.provision "shell", path: "scripts/vagrant_provision.sh", env: {
    "RUN_WAZUH" => ENV.fetch("RUN_WAZUH", "0")
  }
end
