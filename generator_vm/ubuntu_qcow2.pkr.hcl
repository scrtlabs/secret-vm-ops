packer {
  required_plugins {
    qemu = {
      version = ">= 1.0.6"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

source "qemu" "ubuntu_2204" {
    vm_name = "ubuntu-22.qcow2"
    cpus = 2
    disk_interface = "virtio"
    headless = true   
    display = "curses"
    http_directory = "http"
    iso_checksum = "9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
    iso_url = "http://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso"
    iso_target_path = "./iso_images"
    memory = 4096
    net_device = "virtio-net"
    format = "qcow2"
    output_directory = "images"

    boot_wait = "5s"
    ssh_username = "ubuntu"
    ssh_password = "password"
    ssh_wait_timeout = "1000s"
    shutdown_command = "echo 'packer' | sudo -S shutdown -P now"

    boot_steps = [
        ["c<wait>"],
        ["linux /casper/vmlinuz --- autoinstall ds=\"nocloud-net;seedfrom=http://{{.HTTPIP}}:{{.HTTPPort}}/\""],
        ["<enter><wait>"],
        ["initrd /casper/initrd"],
        ["<enter><wait>"],
        ["boot"],
        ["<enter>"],
        ["<wait180>"]
    ]
}

build {
  sources = ["source.qemu.ubuntu_2204"]

  provisioner "file" {
    source      = "./upload"
    destination = "/tmp/upload"
  }

  provisioner "shell" {
    inline = [
      "echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-ubuntu2-nopasswd",
      "sudo chmod 440 /etc/sudoers.d/90-ubuntu2-nopasswd"
    ]
  }
}
