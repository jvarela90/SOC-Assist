"""
SOC Assist — MAC OUI Lookup Service
Identifies device manufacturer and category from a MAC address prefix.
Data: curated subset of the IEEE OUI registry (most common vendors).
"""
import re

# OUI table: 6-hex-char prefix (uppercase, no separators) → {vendor, category}
# Categories: Networking, Endpoint, Server, Mobile, Virtual, IoT, Security, Printer, Storage, Other
_OUI_TABLE: dict[str, dict] = {
    # ── VMware / Hypervisors ──────────────────────────────────────────────
    "000C29": {"vendor": "VMware, Inc.",            "category": "Virtual Machine"},
    "000569": {"vendor": "VMware, Inc.",            "category": "Virtual Machine"},
    "001C14": {"vendor": "VMware, Inc.",            "category": "Virtual Machine"},
    "005056": {"vendor": "VMware, Inc.",            "category": "Virtual Machine"},
    "080027": {"vendor": "Oracle VirtualBox",       "category": "Virtual Machine"},
    "525400": {"vendor": "QEMU/KVM (libvirt)",      "category": "Virtual Machine"},
    "00155D": {"vendor": "Microsoft Hyper-V",       "category": "Virtual Machine"},
    "001DD8": {"vendor": "Microsoft Hyper-V",       "category": "Virtual Machine"},
    "AABBCC": {"vendor": "Xen Virtual NIC",         "category": "Virtual Machine"},

    # ── Cisco ─────────────────────────────────────────────────────────────
    "000142": {"vendor": "Cisco Systems",           "category": "Networking"},
    "00000C": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0001C9": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000216": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0002FC": {"vendor": "Cisco Systems",           "category": "Networking"},
    "00037F": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0004C0": {"vendor": "Cisco Systems",           "category": "Networking"},
    "00059A": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0006C1": {"vendor": "Cisco Systems",           "category": "Networking"},
    "00070E": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000895": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000996": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000A8A": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000BB4": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000D29": {"vendor": "Cisco Systems",           "category": "Networking"},
    "000ED7": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0010A6": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001185": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001201": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001310": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001425": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001601": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001A6C": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001BD4": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001CA8": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001E4A": {"vendor": "Cisco Systems",           "category": "Networking"},
    "001F9E": {"vendor": "Cisco Systems",           "category": "Networking"},
    "002155": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0021A0": {"vendor": "Cisco Systems",           "category": "Networking"},
    "002368": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0023BE": {"vendor": "Cisco Systems",           "category": "Networking"},
    "002601": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0026CB": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0050E2": {"vendor": "Cisco Systems",           "category": "Networking"},
    "0060B0": {"vendor": "Cisco Systems",           "category": "Networking"},
    "00E014": {"vendor": "Cisco Systems",           "category": "Networking"},
    "58F39C": {"vendor": "Cisco Systems",           "category": "Networking"},
    "6CB217": {"vendor": "Cisco Systems",           "category": "Networking"},
    "7CF7F5": {"vendor": "Cisco Systems",           "category": "Networking"},
    "84B2BE": {"vendor": "Cisco Systems",           "category": "Networking"},
    "886370": {"vendor": "Cisco Systems",           "category": "Networking"},
    "C84C75": {"vendor": "Cisco Systems",           "category": "Networking"},
    "D824BD": {"vendor": "Cisco Systems",           "category": "Networking"},
    "E8ED05": {"vendor": "Cisco Systems",           "category": "Networking"},
    "F44E05": {"vendor": "Cisco Systems",           "category": "Networking"},
    "F87B20": {"vendor": "Cisco Systems",           "category": "Networking"},

    # ── Cisco Meraki ─────────────────────────────────────────────────────
    "0C8112": {"vendor": "Cisco Meraki",            "category": "Networking"},
    "882BDB": {"vendor": "Cisco Meraki",            "category": "Networking"},
    "E0CB4E": {"vendor": "Cisco Meraki",            "category": "Networking"},

    # ── Juniper Networks ─────────────────────────────────────────────────
    "000A59": {"vendor": "Juniper Networks",        "category": "Networking"},
    "001BC0": {"vendor": "Juniper Networks",        "category": "Networking"},
    "0019E2": {"vendor": "Juniper Networks",        "category": "Networking"},
    "286ED4": {"vendor": "Juniper Networks",        "category": "Networking"},
    "3C614C": {"vendor": "Juniper Networks",        "category": "Networking"},
    "5C5EAB": {"vendor": "Juniper Networks",        "category": "Networking"},
    "647987": {"vendor": "Juniper Networks",        "category": "Networking"},
    "8418AA": {"vendor": "Juniper Networks",        "category": "Networking"},
    "B0C69A": {"vendor": "Juniper Networks",        "category": "Networking"},

    # ── Aruba / HP Networking ────────────────────────────────────────────
    "001A1E": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},
    "00247D": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},
    "24DE C6": {"vendor": "Aruba Networks (HPE)",   "category": "Networking"},
    "6C8814": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},
    "9C1C12": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},
    "AC3744": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},
    "D8C7C8": {"vendor": "Aruba Networks (HPE)",    "category": "Networking"},

    # ── Fortinet ──────────────────────────────────────────────────────────
    "0009OF": {"vendor": "Fortinet",                "category": "Security"},
    "00090F": {"vendor": "Fortinet",                "category": "Security"},
    "001832": {"vendor": "Fortinet",                "category": "Security"},
    "70886B": {"vendor": "Fortinet",                "category": "Security"},
    "90BCA9": {"vendor": "Fortinet",                "category": "Security"},
    "A8732E": {"vendor": "Fortinet",                "category": "Security"},
    "E83A12": {"vendor": "Fortinet",                "category": "Security"},

    # ── Palo Alto Networks ───────────────────────────────────────────────
    "001B17": {"vendor": "Palo Alto Networks",      "category": "Security"},
    "002338": {"vendor": "Palo Alto Networks",      "category": "Security"},
    "708BCD": {"vendor": "Palo Alto Networks",      "category": "Security"},
    "B4B6BE": {"vendor": "Palo Alto Networks",      "category": "Security"},

    # ── Check Point ─────────────────────────────────────────────────────
    "000EA5": {"vendor": "Check Point Software",    "category": "Security"},
    "001B17": {"vendor": "Check Point Software",    "category": "Security"},

    # ── HP / Hewlett-Packard ──────────────────────────────────────────────
    "00306E": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "001083": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "0017A4": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "001AA0": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "001CC4": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "001E0B": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "001FE2": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "002354": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "3C4A92": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "5CD947": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "A04362": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "B499BA": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "D0BF9C": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},
    "E4E763": {"vendor": "Hewlett-Packard",         "category": "Endpoint"},

    # ── Dell ─────────────────────────────────────────────────────────────
    "000874": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "001372": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "001A4B": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "0021F6": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "002564": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "14187A": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "18A99B": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "24B6FD": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "2C44FD": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "34179E": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "3863BB": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "3C2C30": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "50C5F5": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "5C26A1": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "74867A": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "78454A": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "84A9C4": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "8C847D": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "A41F72": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "A4BADB": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "B083FE": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "BCAE8A": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "C81F66": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "D067E5": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "D4BE D9": {"vendor": "Dell Technologies",      "category": "Endpoint"},
    "E4B97A": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "F0A30E": {"vendor": "Dell Technologies",       "category": "Endpoint"},
    "F08E77": {"vendor": "Dell Technologies",       "category": "Endpoint"},

    # ── Lenovo ───────────────────────────────────────────────────────────
    "0017FA": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "001E4D": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "002275": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "4CCC6A": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "54EE75": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "60D9C7": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "7491BB": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "8C8590": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "9C4EDF": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "A44C11": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "C890D9": {"vendor": "Lenovo",                  "category": "Endpoint"},
    "D4C9EF": {"vendor": "Lenovo",                  "category": "Endpoint"},

    # ── Apple ────────────────────────────────────────────────────────────
    "000A27": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "000D93": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001124": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001451": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "0016CB": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "0017F2": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001921": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001B63": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001CF0": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001D4F": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001EC2": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "001FF3": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "0021E9": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "002332": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "0023DF": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "002500": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "002608": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "0026B9": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "28CFE9": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "3C0754": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "3CE072": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "4C57CA": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "6C4008": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "70700D": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "7CC537": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "98FE94": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "A4C361": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "B8C75D": {"vendor": "Apple, Inc.",             "category": "Mobile"},
    "D4F46F": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "DC2B2A": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "E4CE8F": {"vendor": "Apple, Inc.",             "category": "Endpoint"},
    "F0D1A9": {"vendor": "Apple, Inc.",             "category": "Mobile"},

    # ── Samsung ──────────────────────────────────────────────────────────
    "002339": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "08ECA9": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "0CF3EE": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "14499B": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "1C62B8": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "20D390": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "2C54CF": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "380195": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "3C0B71": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "40B76A": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "4C3C16": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "5001BB": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "5417F3": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "5C3C27": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "6C2F2C": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "6C8336": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "7050E7": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "7486E2": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "840BB2": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "8C71F8": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "9C65F9": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "A026B9": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "B83E59": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "C819F7": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "D4879A": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "E4323C": {"vendor": "Samsung Electronics",     "category": "Mobile"},
    "F4F5E8": {"vendor": "Samsung Electronics",     "category": "Mobile"},

    # ── Microsoft ────────────────────────────────────────────────────────
    "0003FF": {"vendor": "Microsoft Corporation",   "category": "Endpoint"},
    "0050F2": {"vendor": "Microsoft Corporation",   "category": "Endpoint"},
    "001DD8": {"vendor": "Microsoft Corporation",   "category": "Endpoint"},
    "7845C4": {"vendor": "Microsoft Corporation",   "category": "Endpoint"},
    "C8DD08": {"vendor": "Microsoft Corporation",   "category": "Endpoint"},

    # ── Intel (NICs) ─────────────────────────────────────────────────────
    "001111": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "001320": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "001B21": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "001E65": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "00248D": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "3C970E": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "4CE17A": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "60F677": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "8086F2": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "A4C3F0": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "E8B4C8": {"vendor": "Intel Corporation",       "category": "Endpoint"},
    "F8341F": {"vendor": "Intel Corporation",       "category": "Endpoint"},

    # ── Broadcom (common in servers) ─────────────────────────────────────
    "000AF7": {"vendor": "Broadcom Corp.",          "category": "Server"},
    "001018": {"vendor": "Broadcom Corp.",          "category": "Server"},
    "003048": {"vendor": "Broadcom Corp.",          "category": "Server"},
    "082578": {"vendor": "Broadcom Corp.",          "category": "Server"},

    # ── Raspberry Pi Foundation ───────────────────────────────────────────
    "B827EB": {"vendor": "Raspberry Pi Foundation", "category": "IoT"},
    "DC A6 32": {"vendor": "Raspberry Pi Trading", "category": "IoT"},
    "DCA632": {"vendor": "Raspberry Pi Trading",   "category": "IoT"},
    "E45F01": {"vendor": "Raspberry Pi Trading",   "category": "IoT"},

    # ── Ubiquiti Networks ─────────────────────────────────────────────────
    "001040": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "002722": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "0418D6": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "18E829": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "24A43C": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "44D9E7": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "60227E": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "68D79A": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "788A20": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "80219A": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "E063DA": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "F09FC2": {"vendor": "Ubiquiti Networks",       "category": "Networking"},
    "FC ECE9": {"vendor": "Ubiquiti Networks",      "category": "Networking"},
    "FCECE9": {"vendor": "Ubiquiti Networks",       "category": "Networking"},

    # ── Huawei ───────────────────────────────────────────────────────────
    "001E10": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "002568": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "00259E": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "003048": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "0090E8": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "00E0FC": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "1C1D67": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "286ED4": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "34DCAD": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "3C47C9": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "40A68F": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "4CAC0A": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "6C8B2F": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "707232": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "7CBDB6": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "88D543": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "9CC172": {"vendor": "Huawei Technologies",     "category": "Networking"},
    "A08CF8": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "ACE215": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "B4430D": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "C8D15E": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "D0271B": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "D46AA8": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "E0244B": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "EC388F": {"vendor": "Huawei Technologies",     "category": "Mobile"},
    "F84ABF": {"vendor": "Huawei Technologies",     "category": "Mobile"},

    # ── Arista Networks ──────────────────────────────────────────────────
    "002823": {"vendor": "Arista Networks",         "category": "Networking"},
    "444C60": {"vendor": "Arista Networks",         "category": "Networking"},
    "74837C": {"vendor": "Arista Networks",         "category": "Networking"},

    # ── Netgear ──────────────────────────────────────────────────────────
    "001B2F": {"vendor": "Netgear",                 "category": "Networking"},
    "001E2A": {"vendor": "Netgear",                 "category": "Networking"},
    "002338": {"vendor": "Netgear",                 "category": "Networking"},
    "08028E": {"vendor": "Netgear",                 "category": "Networking"},
    "20E52A": {"vendor": "Netgear",                 "category": "Networking"},
    "28C68E": {"vendor": "Netgear",                 "category": "Networking"},
    "30469A": {"vendor": "Netgear",                 "category": "Networking"},
    "44944D": {"vendor": "Netgear",                 "category": "Networking"},
    "6CIDE 4": {"vendor": "Netgear",                "category": "Networking"},
    "A021B7": {"vendor": "Netgear",                 "category": "Networking"},
    "C03F0E": {"vendor": "Netgear",                 "category": "Networking"},
    "E09158": {"vendor": "Netgear",                 "category": "Networking"},

    # ── TP-Link ──────────────────────────────────────────────────────────
    "14CFE2": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "1C3BF3": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "207BD2": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "3C46D8": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "5CA4D4": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "64FB81": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "74DA38": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "80AB03": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "90F652": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "A42BB0": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "B0487A": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "D46E5C": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "E4A7A0": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "F05C19": {"vendor": "TP-Link Technologies",    "category": "Networking"},
    "F4EC38": {"vendor": "TP-Link Technologies",    "category": "Networking"},

    # ── Printers ─────────────────────────────────────────────────────────
    "0004EA": {"vendor": "Epson",                   "category": "Printer"},
    "00085B": {"vendor": "Canon",                   "category": "Printer"},
    "000D93": {"vendor": "Epson",                   "category": "Printer"},
    "000EA6": {"vendor": "Brother Industries",      "category": "Printer"},
    "0010A4": {"vendor": "Xerox Corporation",       "category": "Printer"},
    "00104B": {"vendor": "3COM/HP",                 "category": "Printer"},
    "001289": {"vendor": "Kyocera Communications",  "category": "Printer"},
    "00144F": {"vendor": "Canon",                   "category": "Printer"},
    "001871": {"vendor": "Ricoh Company",           "category": "Printer"},
    "00194E": {"vendor": "Lexmark International",   "category": "Printer"},
    "001B78": {"vendor": "Konica Minolta",          "category": "Printer"},
    "0023AE": {"vendor": "Konica Minolta",          "category": "Printer"},
    "00805F": {"vendor": "Ricoh Company",           "category": "Printer"},
    "00E0EE": {"vendor": "Xerox Corporation",       "category": "Printer"},
    "4061EF": {"vendor": "Canon",                   "category": "Printer"},
    "485B39": {"vendor": "Hewlett-Packard (Printer)","category": "Printer"},
    "A4BA76": {"vendor": "Hewlett-Packard (Printer)","category": "Printer"},
    "D4E880": {"vendor": "Brother Industries",      "category": "Printer"},

    # ── Storage / NAS ────────────────────────────────────────────────────
    "0010F3": {"vendor": "QNAP Systems",            "category": "Storage"},
    "001FC8": {"vendor": "QNAP Systems",            "category": "Storage"},
    "002590": {"vendor": "Western Digital (WD)",    "category": "Storage"},
    "00265A": {"vendor": "Synology",                "category": "Storage"},
    "001132": {"vendor": "Synology",                "category": "Storage"},
    "0015E9": {"vendor": "Western Digital (WD)",    "category": "Storage"},
    "0050F2": {"vendor": "NetApp",                  "category": "Storage"},
    "00A098": {"vendor": "NetApp",                  "category": "Storage"},
    "201702": {"vendor": "Synology",                "category": "Storage"},
    "BC3400": {"vendor": "Synology",                "category": "Storage"},

    # ── Servers ──────────────────────────────────────────────────────────
    "001E4F": {"vendor": "HP ProLiant (iLO)",       "category": "Server"},
    "0017A4": {"vendor": "HP ProLiant",             "category": "Server"},
    "5C260A": {"vendor": "IBM (Lenovo System X)",   "category": "Server"},
    "00096E": {"vendor": "IBM",                     "category": "Server"},
    "D0940E": {"vendor": "Super Micro Computer",    "category": "Server"},
    "AC1F6B": {"vendor": "Super Micro Computer",    "category": "Server"},

    # ── Cameras / CCTV ───────────────────────────────────────────────────
    "002017": {"vendor": "Axis Communications",     "category": "IoT"},
    "ACCC8E": {"vendor": "Hikvision",               "category": "IoT"},
    "C0B8CB": {"vendor": "Hikvision",               "category": "IoT"},
    "4C6490": {"vendor": "Dahua Technology",        "category": "IoT"},
    "28571B": {"vendor": "Dahua Technology",        "category": "IoT"},
    "E04F43": {"vendor": "Axis Communications",     "category": "IoT"},

    # ── Smart devices / IoT ──────────────────────────────────────────────
    "18B433": {"vendor": "Amazon Echo / Alexa",     "category": "IoT"},
    "28EF01": {"vendor": "Amazon (Kindle/Fire)",    "category": "IoT"},
    "40B4CD": {"vendor": "Amazon Technologies",     "category": "IoT"},
    "74C246": {"vendor": "Amazon Technologies",     "category": "IoT"},
    "6C5665": {"vendor": "Philips Hue (Signify)",   "category": "IoT"},
    "EC1BBD": {"vendor": "Philips Hue (Signify)",   "category": "IoT"},
    "001D1E": {"vendor": "Google LLC",              "category": "IoT"},
    "3C5AB4": {"vendor": "Google (Chromecast)",     "category": "IoT"},
    "54607E": {"vendor": "Google LLC",              "category": "IoT"},
    "94EB2C": {"vendor": "Google LLC",              "category": "IoT"},
    "F88FCA": {"vendor": "Google (Nest)",           "category": "IoT"},

    # ── Miscellaneous / Other Common ─────────────────────────────────────
    "000000": {"vendor": "Xerox Corp. (historical/test)", "category": "Other"},
    "FFFFFFFFFFFF": {"vendor": "Broadcast Address",  "category": "Other"},
}

# Category icons for display
CATEGORY_ICONS = {
    "Virtual Machine": "bi-pc-display",
    "Networking":      "bi-router-fill",
    "Security":        "bi-shield-check",
    "Endpoint":        "bi-laptop",
    "Server":          "bi-server",
    "Mobile":          "bi-phone",
    "Printer":         "bi-printer",
    "Storage":         "bi-hdd-stack",
    "IoT":             "bi-cpu",
    "Other":           "bi-question-circle",
}

# Normalize OUI table keys (remove spaces, uppercase)
_OUI_NORMALIZED: dict[str, dict] = {}
for _k, _v in _OUI_TABLE.items():
    _key = _k.replace(" ", "").upper()
    if len(_key) == 6:
        _OUI_NORMALIZED[_key] = _v


def normalize_mac(mac: str) -> str | None:
    """Strip all separators, uppercase, validate length."""
    clean = re.sub(r'[:\-\.\s]', '', mac.strip().upper())
    if not re.fullmatch(r'[0-9A-F]{12}', clean):
        return None
    return clean


def lookup_mac(mac: str) -> dict:
    """
    Look up a MAC address to get vendor and device category.

    Returns:
        {
          "mac_normalized": "001A2B3C4D5E",
          "oui": "001A2B",
          "vendor": "Some Vendor" | "Desconocido",
          "category": "Networking" | … | "Desconocido",
          "icon": "bi-router-fill" | …,
          "found": True/False
        }
    """
    normalized = normalize_mac(mac)
    if normalized is None:
        return {
            "error": "Formato de MAC inválido. Use XX:XX:XX:XX:XX:XX o similar.",
            "found": False,
        }

    oui = normalized[:6]
    entry = _OUI_NORMALIZED.get(oui)

    if entry:
        return {
            "mac_normalized": normalized,
            "oui": oui,
            "vendor": entry["vendor"],
            "category": entry["category"],
            "icon": CATEGORY_ICONS.get(entry["category"], "bi-question-circle"),
            "found": True,
        }

    return {
        "mac_normalized": normalized,
        "oui": oui,
        "vendor": "Desconocido",
        "category": "Desconocido",
        "icon": "bi-question-circle",
        "found": False,
    }
