static __attribute__((unused)) const char *generator = "../buildtools/pmdinfogen.py";
const char net_txgbe_pmd_info[] __attribute__((used)) = "PMD_INFO_STRING= {\"name\": \"net_txgbe\", \"params\": \"auto_neg=<0|1>poll=<0|1>present=<0|1>sgmii=<0|1>ffe_set=<0-4>ffe_main=<uint16>ffe_pre=<uint16>ffe_post=<uint16>\", \"kmod\": \"* igb_uio | uio_pci_generic | vfio-pci\", \"pci_ids\": [[32904, 4097, 65535, 65535], [32904, 8193, 65535, 65535]]}";
const char net_txgbe_vf_pmd_info[] __attribute__((used)) = "PMD_INFO_STRING= {\"name\": \"net_txgbe_vf\", \"kmod\": \"* igb_uio | vfio-pci\", \"pci_ids\": [[32904, 4096, 65535, 65535], [32904, 8192, 65535, 65535]]}";
