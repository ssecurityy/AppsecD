"""License compliance checker for SCA dependencies.

Comprehensive license database with 200+ SPDX identifiers, compatibility matrix,
obligation tracking, and SPDX expression parsing (OR/AND/WITH).
"""
import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. License Risk Classification  (200+ SPDX identifiers)
# ---------------------------------------------------------------------------
# Risk levels:
#   "high"   — strong copyleft / network-copyleft / source-available restrictive
#   "medium" — weak copyleft / file-level copyleft / conditional restrictions
#   "low"    — permissive
#   "none"   — public domain / no restrictions
# Anything not listed will be classified as "unknown".

LICENSE_RISK: dict[str, str] = {
    # ===== HIGH RISK — strong copyleft / network copyleft / restrictive =====
    # GPL family
    "GPL-1.0-only":       "high",
    "GPL-1.0-or-later":   "high",
    "GPL-2.0":            "high",
    "GPL-2.0-only":       "high",
    "GPL-2.0-or-later":   "high",
    "GPL-3.0":            "high",
    "GPL-3.0-only":       "high",
    "GPL-3.0-or-later":   "high",
    # AGPL family
    "AGPL-1.0-only":      "high",
    "AGPL-1.0-or-later":  "high",
    "AGPL-3.0":           "high",
    "AGPL-3.0-only":      "high",
    "AGPL-3.0-or-later":  "high",
    # Source-available / non-compete / restrictive
    "SSPL-1.0":           "high",
    "Elastic-2.0":        "high",
    "BSL-1.1":            "high",
    "RSAL":               "high",
    "Commons-Clause":     "high",
    # European / regional copyleft
    "EUPL-1.0":           "high",
    "EUPL-1.1":           "high",
    "EUPL-1.2":           "high",
    # Other strong copyleft
    "OSL-1.0":            "high",
    "OSL-2.0":            "high",
    "OSL-2.1":            "high",
    "OSL-3.0":            "high",
    "RPL-1.1":            "high",
    "RPL-1.5":            "high",
    "QPL-1.0":            "high",
    "QPL-1.0-INRIA-2004": "high",
    "Sleepycat":          "high",
    "Watcom-1.0":         "high",
    "CPAL-1.0":           "high",
    "SISSL":              "high",
    "SPL-1.0":            "high",
    "CECILL-2.0":         "high",
    "NASA-1.3":           "high",
    "RHeCos-1.1":         "high",
    "RPL-1.1":            "high",
    "Interbase-1.0":      "high",
    # CC non-commercial / no-derivatives
    "CC-BY-NC-1.0":       "high",
    "CC-BY-NC-2.0":       "high",
    "CC-BY-NC-2.5":       "high",
    "CC-BY-NC-3.0":       "high",
    "CC-BY-NC-4.0":       "high",
    "CC-BY-NC-SA-1.0":    "high",
    "CC-BY-NC-SA-2.0":    "high",
    "CC-BY-NC-SA-2.5":    "high",
    "CC-BY-NC-SA-3.0":    "high",
    "CC-BY-NC-SA-4.0":    "high",
    "CC-BY-NC-ND-1.0":    "high",
    "CC-BY-NC-ND-2.0":    "high",
    "CC-BY-NC-ND-2.5":    "high",
    "CC-BY-NC-ND-3.0":    "high",
    "CC-BY-NC-ND-4.0":    "high",
    "CC-BY-ND-4.0":       "high",
    # LGPL (high risk when statically linked or modified)
    "LGPL-2.0":           "high",
    "LGPL-2.0-only":      "high",
    "LGPL-2.1":           "high",
    "LGPL-2.1-only":      "high",
    "LGPL-3.0":           "high",
    "LGPL-3.0-only":      "high",
    # Affero variants
    "APSL-1.0":           "high",
    "APSL-1.1":           "high",
    "APSL-1.2":           "high",
    # JSON license (restrictive "shall be used for Good, not Evil")
    "JSON":               "high",

    # ===== MEDIUM RISK — weak copyleft / file-level copyleft =====
    # Mozilla Public License
    "MPL-1.0":            "medium",
    "MPL-1.1":            "medium",
    "MPL-2.0":            "medium",
    "MPL-2.0-no-copyleft-exception": "medium",
    # Eclipse Public License
    "EPL-1.0":            "medium",
    "EPL-2.0":            "medium",
    # Common Development and Distribution License
    "CDDL-1.0":          "medium",
    "CDDL-1.1":          "medium",
    # LGPL "or-later" variants (medium: dynamic linking OK)
    "LGPL-2.0-or-later":  "medium",
    "LGPL-2.1-or-later":  "medium",
    "LGPL-3.0-or-later":  "medium",
    # Other weak copyleft
    "CPL-1.0":            "medium",
    "IPL-1.0":            "medium",
    "Ms-RL":              "medium",
    "MS-RL":              "medium",
    "APSL-2.0":           "medium",
    "Artistic-1.0":       "medium",
    "Artistic-2.0":       "medium",
    "CeCILL-2.1":         "medium",
    "CECILL-2.1":         "medium",
    "LPPL-1.0":           "medium",
    "LPPL-1.1":           "medium",
    "LPPL-1.2":           "medium",
    "LPPL-1.3a":          "medium",
    "LPPL-1.3c":          "medium",
    # CC Share-Alike
    "CC-BY-SA-1.0":       "medium",
    "CC-BY-SA-2.0":       "medium",
    "CC-BY-SA-2.5":       "medium",
    "CC-BY-SA-3.0":       "medium",
    "CC-BY-SA-4.0":       "medium",
    # Open Font License
    "OFL-1.0":            "medium",
    "OFL-1.1":            "medium",
    "OFL-1.1-RFN":        "medium",
    "OFL-1.1-no-RFN":     "medium",
    # Polyform / Functional Source / delayed open-source
    "Polyform-Shield-1.0.0":       "medium",
    "Polyform-Free-Trial-1.0.0":   "medium",
    "Polyform-Noncommercial-1.0.0": "medium",
    "Polyform-Small-Business-1.0.0": "medium",
    "Polyform-Strict-1.0.0":       "medium",
    "FSL-1.0-MIT":                 "medium",
    "FSL-1.0-Apache-2.0":          "medium",
    "FSL-1.1-MIT":                 "medium",
    "FSL-1.1-Apache-2.0":          "medium",
    # Other medium risk
    "Motosoto":           "medium",
    "Nokia":              "medium",
    "OGTSL":              "medium",
    "RPSL-1.0":           "medium",
    "SimPL-2.0":          "medium",
    "Frameworx-1.0":      "medium",
    "EFL-1.0":            "medium",
    "EFL-2.0":            "medium",
    "LPL-1.0":            "medium",
    "LPL-1.02":           "medium",
    "CATOSL-1.1":         "medium",
    "CUA-OPL-1.0":        "medium",
    "Entessa":            "medium",
    "IPA":                "medium",
    "Multics":            "medium",
    "NGPL":               "medium",
    "NPOSL-3.0":          "medium",
    "UPL-1.0":            "medium",
    "WXwindows":          "medium",
    "Xnet":               "medium",
    "YPL-1.1":            "medium",
    "Zimbra-1.3":         "medium",
    "Zimbra-1.4":         "medium",
    "Condor-1.1":         "medium",
    "CNRI-Python-GPL-Compatible": "medium",
    "LAL-1.2":            "medium",
    "LAL-1.3":            "medium",

    # ===== LOW RISK — permissive =====
    # MIT variants
    "MIT":                "low",
    "MIT-0":              "low",
    "MIT-CMU":            "low",
    "MIT-advertising":    "low",
    "MIT-enna":           "low",
    "MIT-feh":            "low",
    "MIT-Modern-Variant":  "low",
    "MIT-open-group":     "low",
    "MITNFA":             "low",
    # Apache
    "Apache-1.0":         "low",
    "Apache-1.1":         "low",
    "Apache-2.0":         "low",
    # BSD variants
    "BSD-1-Clause":       "low",
    "BSD-2-Clause":       "low",
    "BSD-2-Clause-Patent": "low",
    "BSD-2-Clause-Views":  "low",
    "BSD-3-Clause":       "low",
    "BSD-3-Clause-LBNL":  "low",
    "BSD-3-Clause-Clear":  "low",
    "BSD-3-Clause-No-Nuclear-License": "low",
    "BSD-3-Clause-No-Nuclear-License-2014": "low",
    "BSD-3-Clause-No-Nuclear-Warranty": "low",
    "BSD-3-Clause-Open-MPI": "low",
    "BSD-3-Clause-Attribution": "low",
    "BSD-4-Clause":       "low",
    "BSD-4-Clause-Shortened": "low",
    "BSD-4-Clause-UC":    "low",
    "BSD-4.3RENO":        "low",
    "BSD-4.3TAHOE":       "low",
    "BSD-Protection":     "low",
    "BSD-Source-Code":     "low",
    # ISC / Internet Systems
    "ISC":                "low",
    # Zlib / libpng
    "Zlib":               "low",
    "zlib-acknowledgement": "low",
    "libpng":             "low",
    "libpng-2.0":         "low",
    # Boost
    "BSL-1.0":            "low",
    # PostgreSQL
    "PostgreSQL":         "low",
    # Python
    "PSF-2.0":            "low",
    "Python-2.0":         "low",
    "Python-2.0.1":       "low",
    "CNRI-Python":        "low",
    # BlueOak
    "BlueOak-1.0.0":      "low",
    # Creative Commons (attribution only, no SA/NC/ND)
    "CC-BY-1.0":          "low",
    "CC-BY-2.0":          "low",
    "CC-BY-2.5":          "low",
    "CC-BY-3.0":          "low",
    "CC-BY-3.0-AT":       "low",
    "CC-BY-3.0-US":       "low",
    "CC-BY-4.0":          "low",
    # X11 / NTP / NCSA / HPND
    "X11":                "low",
    "X11-distribute-modifications-variant": "low",
    "NTP":                "low",
    "NTP-0":              "low",
    "NCSA":               "low",
    "HPND":               "low",
    "HPND-sell-variant":  "low",
    # Vim
    "Vim":                "low",
    # MulanPSL
    "MulanPSL-1.0":       "low",
    "MulanPSL-2.0":       "low",
    # Microsoft permissive
    "MS-PL":              "low",
    "Ms-PL":              "low",
    # ECL
    "ECL-1.0":            "low",
    "ECL-2.0":            "low",
    # curl
    "curl":               "low",
    # Unicode
    "Unicode-DFS-2015":   "low",
    "Unicode-DFS-2016":   "low",
    "Unicode-TOU":        "low",
    # Fair
    "Fair":               "low",
    "FairSource":         "low",
    # AFL
    "AFL-1.1":            "low",
    "AFL-1.2":            "low",
    "AFL-2.0":            "low",
    "AFL-2.1":            "low",
    "AFL-3.0":            "low",
    # Other permissive
    "AAL":                "low",
    "Abstyles":           "low",
    "Adobe-2006":         "low",
    "Adobe-Glyph":        "low",
    "ADSL":               "low",
    "AML":                "low",
    "AMPAS":              "low",
    "ANTLR-PD":           "low",
    "ANTLR-PD-fallback":  "low",
    "Barr":               "low",
    "Beerware":           "low",
    "blessing":           "low",
    "BitTorrent-1.0":     "low",
    "BitTorrent-1.1":     "low",
    "BlueOak-1.0.0":      "low",
    "Borceux":            "low",
    "Brian-Gladman-3-Clause": "low",
    "CAL-1.0":            "low",
    "CAL-1.0-Combined-Work-Exception": "low",
    "Caldera":            "low",
    "ClArtistic":         "low",
    "Crossword":          "low",
    "CrystalStacker":     "low",
    "Cube":               "low",
    "diffmark":           "low",
    "DOC":                "low",
    "Dotseqn":            "low",
    "DSDP":               "low",
    "dtoa":               "low",
    "dvipdfm":            "low",
    "eGenix":             "low",
    "Elastic-1.0":        "low",
    "EUDatagrid":         "low",
    "FDK-AAC":            "low",
    "FSFAP":              "low",
    "FSFUL":              "low",
    "FSFULLR":            "low",
    "FTL":                "low",
    "GD":                 "low",
    "GL2PS":              "low",
    "Glide":              "low",
    "Glulxe":             "low",
    "HTMLTIDY":           "low",
    "IBM-pibs":           "low",
    "ICU":                "low",
    "IJG":                "low",
    "ImageMagick":        "low",
    "iMatix":             "low",
    "Info-ZIP":           "low",
    "Intel":              "low",
    "Intel-ACPI":         "low",
    "JPNIC":              "low",
    "Latex2e":            "low",
    "Latex2e-translated-notice": "low",
    "Leptonica":          "low",
    "LGPLLR":             "low",
    "Libpng":             "low",
    "libtiff":            "low",
    "LiLiQ-P-1.1":       "low",
    "Linux-OpenIB":       "low",
    "MakeIndex":          "low",
    "MIT-Festival":       "low",
    "MTLL":               "low",
    "Naumen":             "low",
    "Net-SNMP":           "low",
    "NetCDF":             "low",
    "Newsletr":           "low",
    "NLOD-1.0":           "low",
    "NLOD-2.0":           "low",
    "NRL":                "low",
    "OLDAP-2.8":          "low",
    "OML":                "low",
    "OpenSSL":            "low",
    "PHP-3.0":            "low",
    "PHP-3.01":           "low",
    "Plexus":             "low",
    "psfrag":             "low",
    "psutils":            "low",
    "Qhull":              "low",
    "Rdisc":              "low",
    "RSA-MD":             "low",
    "Ruby":               "low",
    "SAX-PD":             "low",
    "Saxpath":            "low",
    "SCEA":               "low",
    "Sendmail":           "low",
    "Sendmail-8.23":      "low",
    "SGI-B-2.0":          "low",
    "SHL-0.5":            "low",
    "SHL-0.51":           "low",
    "SMPPL":              "low",
    "SNIA":               "low",
    "Spencer-86":         "low",
    "Spencer-94":         "low",
    "Spencer-99":         "low",
    "SSH-OpenSSH":        "low",
    "SSH-short":          "low",
    "SSLeay-standalone":  "low",
    "SunPro":             "low",
    "SWL":                "low",
    "TCL":                "low",
    "TCP-wrappers":       "low",
    "TMate":              "low",
    "TU-Berlin-1.0":      "low",
    "TU-Berlin-2.0":      "low",
    "UCL-1.0":            "low",
    "W3C":                "low",
    "W3C-19980720":       "low",
    "W3C-20150513":       "low",
    "Wsuipa":             "low",
    "WTFPL":              "low",
    "XFree86-1.1":        "low",
    "xinetd":             "low",
    "Xpp":                "low",
    "Zend-2.0":           "low",
    "ZPL-1.1":            "low",
    "ZPL-2.0":            "low",
    "ZPL-2.1":            "low",

    # ===== NONE — public domain / truly unrestricted =====
    "Unlicense":          "none",
    "CC0-1.0":            "none",
    "0BSD":               "none",
    "PDDL-1.0":           "none",
    "Public-Domain":      "none",
    "blessing":           "none",
    "SAX-PD":             "none",
}

# ---------------------------------------------------------------------------
# 2. Common License Name Normalization (alias -> SPDX)
# ---------------------------------------------------------------------------

_ALIASES: dict[str, str] = {
    # Apache
    "apache 2.0":               "Apache-2.0",
    "apache-2":                 "Apache-2.0",
    "apache 2":                 "Apache-2.0",
    "apache-2.0":               "Apache-2.0",
    "apache license 2.0":       "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license":  "Apache-2.0",
    "apache license":           "Apache-2.0",
    "asf 2.0":                  "Apache-2.0",
    "al-2.0":                   "Apache-2.0",
    "apache v2":                "Apache-2.0",
    "apache v2.0":              "Apache-2.0",
    # MIT
    "mit license":              "MIT",
    "mit":                      "MIT",
    "the mit license":          "MIT",
    "expat":                    "MIT",
    "expat license":            "MIT",
    "mit/x11":                  "MIT",
    "x11 license":              "X11",
    "mit-0":                    "MIT-0",
    # BSD
    "bsd":                      "BSD-3-Clause",
    "bsd license":              "BSD-3-Clause",
    "bsd-2":                    "BSD-2-Clause",
    "bsd-3":                    "BSD-3-Clause",
    "bsd 2-clause":             "BSD-2-Clause",
    "bsd 3-clause":             "BSD-3-Clause",
    "bsd-2-clause":             "BSD-2-Clause",
    "bsd-3-clause":             "BSD-3-Clause",
    "bsd 2 clause":             "BSD-2-Clause",
    "bsd 3 clause":             "BSD-3-Clause",
    "simplified bsd":           "BSD-2-Clause",
    "new bsd":                  "BSD-3-Clause",
    "new bsd license":          "BSD-3-Clause",
    "modified bsd":             "BSD-3-Clause",
    "revised bsd":              "BSD-3-Clause",
    "freebsd":                  "BSD-2-Clause",
    "bsd-4-clause":             "BSD-4-Clause",
    "original bsd":             "BSD-4-Clause",
    "0bsd":                     "0BSD",
    # GPL
    "gpl":                      "GPL-3.0",
    "gpl-2":                    "GPL-2.0",
    "gpl-3":                    "GPL-3.0",
    "gpl2":                     "GPL-2.0",
    "gpl3":                     "GPL-3.0",
    "gpl v2":                   "GPL-2.0",
    "gpl v3":                   "GPL-3.0",
    "gplv2":                    "GPL-2.0-only",
    "gplv3":                    "GPL-3.0-only",
    "gpl-2.0":                  "GPL-2.0",
    "gpl-3.0":                  "GPL-3.0",
    "gpl-2.0-only":             "GPL-2.0-only",
    "gpl-3.0-only":             "GPL-3.0-only",
    "gpl-2.0-or-later":         "GPL-2.0-or-later",
    "gpl-3.0-or-later":         "GPL-3.0-or-later",
    "gpl-2.0+":                 "GPL-2.0-or-later",
    "gpl-3.0+":                 "GPL-3.0-or-later",
    "gnu general public license v2": "GPL-2.0",
    "gnu general public license v3": "GPL-3.0",
    "gnu gpl v2":               "GPL-2.0",
    "gnu gpl v3":               "GPL-3.0",
    "gnu general public license": "GPL-3.0",
    # LGPL
    "lgpl":                     "LGPL-3.0",
    "lgpl-2":                   "LGPL-2.0",
    "lgpl-2.0":                 "LGPL-2.0",
    "lgpl-2.1":                 "LGPL-2.1",
    "lgpl-3":                   "LGPL-3.0",
    "lgpl-3.0":                 "LGPL-3.0",
    "lgplv2":                   "LGPL-2.0-only",
    "lgplv2.1":                 "LGPL-2.1-only",
    "lgplv3":                   "LGPL-3.0-only",
    "lgpl-2.1+":                "LGPL-2.1-or-later",
    "lgpl-3.0+":                "LGPL-3.0-or-later",
    "gnu lesser general public license v2": "LGPL-2.0",
    "gnu lesser general public license v2.1": "LGPL-2.1",
    "gnu lesser general public license v3": "LGPL-3.0",
    "gnu lgpl v2.1":            "LGPL-2.1",
    "gnu lgpl v3":              "LGPL-3.0",
    # AGPL
    "agpl":                     "AGPL-3.0",
    "agpl-3":                   "AGPL-3.0",
    "agpl-3.0":                 "AGPL-3.0",
    "agplv3":                   "AGPL-3.0-only",
    "gnu affero gpl v3":        "AGPL-3.0",
    "gnu agpl v3":              "AGPL-3.0",
    # MPL
    "mpl":                      "MPL-2.0",
    "mpl-2":                    "MPL-2.0",
    "mpl-2.0":                  "MPL-2.0",
    "mpl-1.0":                  "MPL-1.0",
    "mpl-1.1":                  "MPL-1.1",
    "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license":   "MPL-2.0",
    # EPL
    "epl":                      "EPL-2.0",
    "epl-1.0":                  "EPL-1.0",
    "epl-2.0":                  "EPL-2.0",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license":   "EPL-2.0",
    # CDDL
    "cddl":                     "CDDL-1.0",
    "cddl-1.0":                 "CDDL-1.0",
    "cddl-1.1":                 "CDDL-1.1",
    # ISC
    "isc license":              "ISC",
    "isc":                      "ISC",
    # Unlicense / CC0 / public domain
    "unlicense":                "Unlicense",
    "the unlicense":            "Unlicense",
    "public domain":            "Public-Domain",
    "pd":                       "Public-Domain",
    "cc0":                      "CC0-1.0",
    "cc0-1.0":                  "CC0-1.0",
    "cc0 1.0":                  "CC0-1.0",
    "cc0 1.0 universal":        "CC0-1.0",
    "pddl":                     "PDDL-1.0",
    "pddl-1.0":                 "PDDL-1.0",
    # WTFPL
    "wtfpl":                    "WTFPL",
    "do what the fuck you want to public license": "WTFPL",
    # Zlib
    "zlib":                     "Zlib",
    "zlib license":             "Zlib",
    "zlib/libpng":              "Zlib",
    # Boost
    "boost":                    "BSL-1.0",
    "bsl-1.0":                  "BSL-1.0",
    "boost software license":   "BSL-1.0",
    "boost software license 1.0": "BSL-1.0",
    # PostgreSQL
    "postgresql":               "PostgreSQL",
    "postgres":                 "PostgreSQL",
    # Python
    "psf":                      "PSF-2.0",
    "psf-2.0":                  "PSF-2.0",
    "python":                   "Python-2.0",
    "psf license":              "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    # Artistic
    "artistic":                 "Artistic-2.0",
    "artistic-1.0":             "Artistic-1.0",
    "artistic-2.0":             "Artistic-2.0",
    "perl":                     "Artistic-2.0",
    "perl license":             "Artistic-2.0",
    # CC-BY
    "cc-by-4.0":                "CC-BY-4.0",
    "cc-by-3.0":                "CC-BY-3.0",
    "cc-by-sa-4.0":             "CC-BY-SA-4.0",
    "cc-by-nc-4.0":             "CC-BY-NC-4.0",
    "creative commons attribution 4.0": "CC-BY-4.0",
    "creative commons attribution": "CC-BY-4.0",
    "cc by 4.0":                "CC-BY-4.0",
    "cc by-sa 4.0":             "CC-BY-SA-4.0",
    "cc by-nc 4.0":             "CC-BY-NC-4.0",
    # OFL
    "ofl":                      "OFL-1.1",
    "ofl-1.1":                  "OFL-1.1",
    "sil open font license":    "OFL-1.1",
    "sil ofl 1.1":              "OFL-1.1",
    # EUPL
    "eupl":                     "EUPL-1.2",
    "eupl-1.2":                 "EUPL-1.2",
    "eupl-1.1":                 "EUPL-1.1",
    # MS-PL / MS-RL
    "ms-pl":                    "MS-PL",
    "microsoft public license":  "MS-PL",
    "ms-rl":                    "MS-RL",
    "microsoft reciprocal license": "MS-RL",
    # SSPL / Elastic / BSL-1.1
    "sspl":                     "SSPL-1.0",
    "sspl-1.0":                 "SSPL-1.0",
    "server side public license": "SSPL-1.0",
    "elastic license":          "Elastic-2.0",
    "elastic-2.0":              "Elastic-2.0",
    "elastic license 2.0":      "Elastic-2.0",
    "bsl-1.1":                  "BSL-1.1",
    "business source license":  "BSL-1.1",
    "busl":                     "BSL-1.1",
    "busl-1.1":                 "BSL-1.1",
    # OSL
    "osl":                      "OSL-3.0",
    "osl-3.0":                  "OSL-3.0",
    # QPL
    "qpl":                      "QPL-1.0",
    "qpl-1.0":                  "QPL-1.0",
    # Ruby
    "ruby":                     "Ruby",
    "ruby license":             "Ruby",
    # PHP
    "php":                      "PHP-3.01",
    "php license":              "PHP-3.01",
    "php-3.0":                  "PHP-3.0",
    "php-3.01":                 "PHP-3.01",
    # OpenSSL
    "openssl":                  "OpenSSL",
    "openssl license":          "OpenSSL",
    # JSON
    "json":                     "JSON",
    "json license":             "JSON",
    # W3C
    "w3c":                      "W3C",
    "w3c license":              "W3C",
    # AFL
    "afl":                      "AFL-3.0",
    "afl-3.0":                  "AFL-3.0",
    # CPL
    "cpl":                      "CPL-1.0",
    "cpl-1.0":                  "CPL-1.0",
    # NCSA
    "ncsa":                     "NCSA",
    "uiuc":                     "NCSA",
    # NTP
    "ntp":                      "NTP",
    # HPND
    "hpnd":                     "HPND",
    # Beerware
    "beerware":                 "Beerware",
    # curl
    "curl":                     "curl",
    "curl license":             "curl",
    # ECL
    "ecl-2.0":                  "ECL-2.0",
    # MulanPSL
    "mulanpsl-2.0":             "MulanPSL-2.0",
    "mulan permissive software license": "MulanPSL-2.0",
    # UPL
    "upl":                      "UPL-1.0",
    "upl-1.0":                  "UPL-1.0",
    # Vim
    "vim":                      "Vim",
    "vim license":              "Vim",
    # Sleepycat
    "sleepycat":                "Sleepycat",
    # Watcom
    "watcom":                   "Watcom-1.0",
    "watcom-1.0":               "Watcom-1.0",
    # BlueOak
    "blueoak":                  "BlueOak-1.0.0",
    "blueoak-1.0.0":            "BlueOak-1.0.0",
    "blue oak":                 "BlueOak-1.0.0",
    "blue oak model license":   "BlueOak-1.0.0",
    # Polyform
    "polyform-shield":          "Polyform-Shield-1.0.0",
    "polyform-noncommercial":   "Polyform-Noncommercial-1.0.0",
    # Fair
    "fair":                     "Fair",
    "fair license":             "Fair",
    # Unicode
    "unicode":                  "Unicode-DFS-2016",
    "unicode-dfs-2016":         "Unicode-DFS-2016",
    # ICU
    "icu":                      "ICU",
    "icu license":              "ICU",
    # ImageMagick
    "imagemagick":              "ImageMagick",
    # NASA
    "nasa-1.3":                 "NASA-1.3",
    # RPL
    "rpl":                      "RPL-1.5",
    "rpl-1.5":                  "RPL-1.5",
    # CPAL
    "cpal":                     "CPAL-1.0",
    "cpal-1.0":                 "CPAL-1.0",
    # RSAL
    "rsal":                     "RSAL",
    "redis source available license": "RSAL",
    # CeCILL
    "cecill":                   "CeCILL-2.1",
    "cecill-2.1":               "CeCILL-2.1",
    # LPPL
    "lppl":                     "LPPL-1.3c",
    "lppl-1.3c":                "LPPL-1.3c",
    "latex project public license": "LPPL-1.3c",
    # Commons-Clause
    "commons clause":           "Commons-Clause",
    "commons-clause":           "Commons-Clause",
    # FSL
    "fsl":                      "FSL-1.0-MIT",
    "functional source license": "FSL-1.0-MIT",
    "fsl-1.0-mit":              "FSL-1.0-MIT",
    "fsl-1.0-apache-2.0":       "FSL-1.0-Apache-2.0",
    # Misc
    "noassertion":              "NOASSERTION",
    "none":                     "NOASSERTION",
    "unknown":                  "NOASSERTION",
    "n/a":                      "NOASSERTION",
    "not specified":            "NOASSERTION",
    "proprietary":              "proprietary",
    "commercial":               "proprietary",
    "custom":                   "proprietary",
}


_DEFAULT_BLOCKED = [
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "AGPL-1.0-only", "AGPL-1.0-or-later",
    "SSPL-1.0", "Elastic-2.0", "BSL-1.1", "RSAL", "Commons-Clause",
]

# ---------------------------------------------------------------------------
# 3. License Compatibility Matrix
# ---------------------------------------------------------------------------
# Maps (project_license, dependency_license) -> True (compatible) / False
# "compatible" means the dependency can legally be included in a project
# distributed under the project license.
#
# Key principles encoded:
#   - Permissive deps are compatible with almost everything.
#   - Copyleft deps are only compatible with same/stronger copyleft projects
#     or permissive projects that *accept* the copyleft terms propagating.
#   - Proprietary projects cannot use strong copyleft deps.
#   - GPL-2.0 and Apache-2.0 are famously incompatible.
#   - GPL-3.0 explicitly resolved the Apache-2.0 incompatibility.
#   - LGPL allows dynamic linking from proprietary code.

# Helper sets for matrix generation
_PERMISSIVE_LICENSES = {
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "CC0-1.0", "0BSD", "WTFPL", "Zlib",
    "BSL-1.0", "PostgreSQL", "PSF-2.0", "Python-2.0", "BlueOak-1.0.0",
    "X11", "Fair", "curl", "libpng-2.0", "NTP", "NCSA", "HPND",
    "CC-BY-4.0", "CC-BY-3.0", "Vim", "MulanPSL-2.0", "MS-PL",
    "ECL-2.0", "Unicode-DFS-2016", "Public-Domain", "PDDL-1.0",
    "W3C", "PHP-3.01", "PHP-3.0", "Ruby", "OpenSSL", "AFL-3.0",
    "BSD-2-Clause-Patent", "BSD-1-Clause", "Beerware", "libpng",
    "Apache-1.0", "Apache-1.1", "ICU", "Intel", "SAX-PD", "SCEA",
    "TCP-wrappers", "Sendmail", "ImageMagick", "Info-ZIP", "SSH-OpenSSH",
}

_STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "AGPL-1.0-only",
    "GPL-1.0-only", "GPL-1.0-or-later",
    "SSPL-1.0", "OSL-3.0", "RPL-1.5", "CPAL-1.0", "Sleepycat",
    "EUPL-1.1", "EUPL-1.2",
}

_WEAK_COPYLEFT = {
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
    "CPL-1.0", "IPL-1.0", "Artistic-2.0", "CeCILL-2.1",
    "LPPL-1.3c", "CC-BY-SA-4.0", "OFL-1.1", "MS-RL",
    "APSL-2.0",
}

_GPL2_FAMILY = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"}
_GPL3_FAMILY = {"GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"}
_AGPL_FAMILY = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-1.0-only"}
_LGPL_FAMILY = {
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
}

# Explicit compatibility matrix for well-known pairs.
# True = compatible, False = incompatible.
COMPATIBILITY_MATRIX: dict[tuple[str, str], bool] = {}

def _build_compatibility_matrix() -> None:
    """Populate COMPATIBILITY_MATRIX with derived rules."""
    m = COMPATIBILITY_MATRIX

    # -------------------------------------------------------------------
    # Rule 1: Permissive project + permissive dep = always OK
    # -------------------------------------------------------------------
    for proj in _PERMISSIVE_LICENSES:
        for dep in _PERMISSIVE_LICENSES:
            m[(proj, dep)] = True

    # -------------------------------------------------------------------
    # Rule 2: Permissive project + copyleft dep = technically OK
    #         (but the copyleft terms propagate — we mark as True with
    #          a caveat note in the checker method)
    # -------------------------------------------------------------------
    for proj in _PERMISSIVE_LICENSES:
        for dep in _STRONG_COPYLEFT | _WEAK_COPYLEFT:
            m[(proj, dep)] = True

    # -------------------------------------------------------------------
    # Rule 3: Copyleft project + permissive dep = always OK
    # -------------------------------------------------------------------
    for proj in _STRONG_COPYLEFT | _WEAK_COPYLEFT:
        for dep in _PERMISSIVE_LICENSES:
            m[(proj, dep)] = True

    # -------------------------------------------------------------------
    # Rule 4: GPL-3.0 project + Apache-2.0 dep = compatible
    # -------------------------------------------------------------------
    for gpl3 in _GPL3_FAMILY:
        m[(gpl3, "Apache-2.0")] = True
        m[("Apache-2.0", gpl3)] = True  # permissive can absorb, terms propagate

    # -------------------------------------------------------------------
    # Rule 5: GPL-2.0 + Apache-2.0 = INCOMPATIBLE (famous case)
    # -------------------------------------------------------------------
    for gpl2 in _GPL2_FAMILY:
        m[(gpl2, "Apache-2.0")] = False
        m[("Apache-2.0", gpl2)] = True  # Apache project using GPL dep: terms propagate

    # -------------------------------------------------------------------
    # Rule 6: GPL family internal compatibility
    # -------------------------------------------------------------------
    for gpl2 in _GPL2_FAMILY:
        for gpl3 in _GPL3_FAMILY:
            # GPL-2.0-only is NOT compatible with GPL-3.0
            if gpl2 == "GPL-2.0-only":
                m[(gpl2, gpl3)] = False
                m[(gpl3, gpl2)] = False
            else:
                # GPL-2.0-or-later can upgrade to GPL-3.0
                m[(gpl2, gpl3)] = True
                m[(gpl3, gpl2)] = True

    # Same GPL version = compatible
    for family in [_GPL2_FAMILY, _GPL3_FAMILY, _AGPL_FAMILY]:
        for a in family:
            for b in family:
                m[(a, b)] = True

    # -------------------------------------------------------------------
    # Rule 7: GPL + AGPL
    # -------------------------------------------------------------------
    for gpl3 in _GPL3_FAMILY:
        for agpl in _AGPL_FAMILY:
            m[(gpl3, agpl)] = True   # GPL-3.0 + AGPL-3.0 compatible
            m[(agpl, gpl3)] = True
    for gpl2 in _GPL2_FAMILY:
        for agpl in _AGPL_FAMILY:
            m[(gpl2, agpl)] = False
            m[(agpl, gpl2)] = False

    # -------------------------------------------------------------------
    # Rule 8: Proprietary + various
    # -------------------------------------------------------------------
    prop = "proprietary"
    for dep in _PERMISSIVE_LICENSES:
        m[(prop, dep)] = True
    for dep in _STRONG_COPYLEFT:
        m[(prop, dep)] = False
    # LGPL with dynamic linking is OK for proprietary
    for dep in _LGPL_FAMILY:
        m[(prop, dep)] = True  # dynamic linking allowed
    # MPL-2.0 file-level copyleft is OK for proprietary (keep modified files MPL)
    m[(prop, "MPL-2.0")] = True
    m[(prop, "EPL-2.0")] = True   # secondary license clause
    m[(prop, "EPL-1.0")] = False  # no secondary license clause
    m[(prop, "CDDL-1.0")] = True  # file-level
    m[(prop, "CDDL-1.1")] = True
    m[(prop, "CPL-1.0")] = False
    m[(prop, "CC-BY-SA-4.0")] = False
    m[(prop, "CC-BY-NC-4.0")] = False
    m[(prop, "CC-BY-NC-SA-4.0")] = False
    m[(prop, "CC-BY-NC-ND-4.0")] = False
    m[(prop, "OFL-1.1")] = True   # fonts OK in proprietary
    m[(prop, "Artistic-2.0")] = True
    m[(prop, "APSL-2.0")] = False
    m[(prop, "BSL-1.1")] = False
    m[(prop, "SSPL-1.0")] = False
    m[(prop, "Elastic-2.0")] = False
    m[(prop, "RSAL")] = False
    m[(prop, "EUPL-1.2")] = False
    m[(prop, "OSL-3.0")] = False

    # -------------------------------------------------------------------
    # Rule 9: Weak copyleft inter-compatibility
    # -------------------------------------------------------------------
    m[("MPL-2.0", "EPL-2.0")] = True
    m[("EPL-2.0", "MPL-2.0")] = True
    m[("MPL-2.0", "CDDL-1.0")] = True
    m[("CDDL-1.0", "MPL-2.0")] = True
    m[("EPL-2.0", "CDDL-1.0")] = True
    m[("CDDL-1.0", "EPL-2.0")] = True
    # MPL-2.0 secondary license clause -> compatible with GPL
    for gpl in _GPL2_FAMILY | _GPL3_FAMILY:
        m[("MPL-2.0", gpl)] = True
        m[(gpl, "MPL-2.0")] = True

    # -------------------------------------------------------------------
    # Rule 10: LGPL + GPL
    # -------------------------------------------------------------------
    for lgpl in _LGPL_FAMILY:
        for gpl in _GPL2_FAMILY | _GPL3_FAMILY:
            m[(lgpl, gpl)] = True  # LGPL project can use GPL (becomes GPL)
            m[(gpl, lgpl)] = True  # GPL project can use LGPL

    # -------------------------------------------------------------------
    # Rule 11: CC licenses mutual compatibility
    # -------------------------------------------------------------------
    m[("CC-BY-4.0", "CC-BY-SA-4.0")] = True
    m[("CC-BY-SA-4.0", "CC-BY-4.0")] = True
    m[("CC-BY-SA-4.0", "CC-BY-SA-4.0")] = True
    m[("CC-BY-4.0", "CC-BY-4.0")] = True

_build_compatibility_matrix()

# ---------------------------------------------------------------------------
# 4. License Obligation Tracking
# ---------------------------------------------------------------------------
# Each obligation key:
#   attribution          — must include copyright notice / license text
#   source_disclosure    — must disclose/offer source code
#   notice_file          — must include a NOTICE file with attributions
#   state_changes        — must document modifications / state changes
#   network_use_disclosure — must disclose source even for network/SaaS use
#   no_endorsement       — may not use author names for endorsement
#   linking_exception    — copyleft applies only if statically linked / modified
#   patent_grant         — includes explicit patent grant
#   patent_retaliation   — license terminates if you sue for patents
#   rename_required      — forks must use a different name
#   same_license         — modifications must remain under same license
#   file_level_copyleft  — copyleft applies per-file, not whole project
#   trademark_restriction — specific trademark use restrictions

OBLIGATIONS: dict[str, dict[str, bool]] = {
    # ---- Permissive ----
    "MIT": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "patent_grant": False,
    },
    "MIT-0": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "patent_grant": False,
    },
    "Apache-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": True,
        "patent_grant": True,
        "patent_retaliation": True,
        "trademark_restriction": True,
    },
    "Apache-1.1": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": False,
    },
    "BSD-2-Clause": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "BSD-3-Clause": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "no_endorsement": True,
    },
    "BSD-4-Clause": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "no_endorsement": True,
    },
    "ISC": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Zlib": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "BSL-1.0": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "PostgreSQL": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "PSF-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Python-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "BlueOak-1.0.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "patent_grant": True,
    },
    "X11": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "curl": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "libpng-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "NTP": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "NCSA": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "no_endorsement": True,
    },
    "HPND": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Fair": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "W3C": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": False,
    },
    "OpenSSL": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": False,
        "no_endorsement": True,
    },
    "PHP-3.01": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "rename_required": True,
    },
    "Ruby": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Unicode-DFS-2016": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Vim": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "MulanPSL-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": False,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "MS-PL": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "patent_grant": True,
    },
    "ECL-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": True,
        "patent_grant": True,
    },
    "AFL-3.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "patent_grant": True,
    },
    "ICU": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "ImageMagick": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": False,
    },
    "Beerware": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "CC-BY-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "CC-BY-3.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },

    # ---- Public domain / no restrictions ----
    "Unlicense": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "CC0-1.0": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "0BSD": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "WTFPL": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "PDDL-1.0": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Public-Domain": {
        "attribution": False,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },

    # ---- Weak copyleft / file-level ----
    "MPL-2.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "file_level_copyleft": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "EPL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "EPL-2.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "CDDL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "file_level_copyleft": True,
        "patent_grant": True,
    },
    "CDDL-1.1": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "file_level_copyleft": True,
        "patent_grant": True,
    },
    "CPL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "IPL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "patent_grant": True,
    },
    "MS-RL": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": False,
        "file_level_copyleft": True,
    },
    "APSL-2.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": True,
        "state_changes": True,
    },
    "Artistic-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
        "rename_required": True,
    },
    "CeCILL-2.1": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "LPPL-1.3c": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
        "rename_required": True,
    },
    "CC-BY-SA-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "OFL-1.1": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
        "rename_required": True,
    },

    # ---- LGPL (linking exception) ----
    "LGPL-2.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-2.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-2.0-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-2.1": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-2.1-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-2.1-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
    },
    "LGPL-3.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
        "patent_grant": True,
    },
    "LGPL-3.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
        "patent_grant": True,
    },
    "LGPL-3.0-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "linking_exception": True,
        "patent_grant": True,
    },

    # ---- Strong copyleft ----
    "GPL-2.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "GPL-2.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "GPL-2.0-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "GPL-3.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "GPL-3.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "GPL-3.0-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "AGPL-3.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "AGPL-3.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "AGPL-3.0-or-later": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
        "patent_grant": True,
        "patent_retaliation": True,
    },
    "AGPL-1.0-only": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
    },

    # ---- Source-available / restrictive ----
    "SSPL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
    },
    "Elastic-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": True,
    },
    "BSL-1.1": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": True,
    },
    "RSAL": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Commons-Clause": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "EUPL-1.1": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "patent_grant": True,
    },
    "EUPL-1.2": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "patent_grant": True,
    },
    "OSL-3.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
        "patent_grant": True,
    },
    "RPL-1.5": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
    },
    "QPL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
    },
    "Sleepycat": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "Watcom-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
    },
    "CPAL-1.0": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
        "network_use_disclosure": True,
    },
    "NASA-1.3": {
        "attribution": True,
        "source_disclosure": True,
        "notice_file": True,
        "state_changes": True,
    },
    "JSON": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },

    # ---- CC non-commercial (representative) ----
    "CC-BY-NC-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
    },
    "CC-BY-NC-SA-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": True,
        "same_license": True,
    },
    "CC-BY-NC-ND-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "CC-BY-ND-4.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },

    # ---- Polyform / FSL ----
    "Polyform-Shield-1.0.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "Polyform-Noncommercial-1.0.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "FSL-1.0-MIT": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": False,
        "state_changes": False,
    },
    "FSL-1.0-Apache-2.0": {
        "attribution": True,
        "source_disclosure": False,
        "notice_file": True,
        "state_changes": True,
    },
}

# ---------------------------------------------------------------------------
# 5. SPDX Exception / WITH Clause Registry
# ---------------------------------------------------------------------------
# Known SPDX exceptions that modify copyleft terms.

SPDX_EXCEPTIONS: dict[str, dict[str, Any]] = {
    "Classpath-exception-2.0": {
        "description": "GNU Classpath exception — allows linking without copyleft propagation",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True, "source_disclosure": False},
    },
    "GCC-exception-3.1": {
        "description": "GCC Runtime Library exception — output not covered by GPL",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "LLVM-exception": {
        "description": "LLVM exception — allows use without copyleft propagation",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Bootloader-exception": {
        "description": "U-Boot exception for bootloader code",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "Autoconf-exception-2.0": {
        "description": "Autoconf exception for generated configure scripts",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Autoconf-exception-3.0": {
        "description": "Autoconf exception v3 for generated configure scripts",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Bison-exception-2.2": {
        "description": "Bison exception for parser output",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Font-exception-2.0": {
        "description": "Font exception — embedding fonts does not trigger copyleft",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "FLTK-exception": {
        "description": "FLTK exception for GUI toolkit linking",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "Libtool-exception": {
        "description": "Libtool exception for generated files",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False},
    },
    "Linux-syscall-note": {
        "description": "Linux syscall note — user-space programs not affected by kernel GPL",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "OpenVPN-openssl-exception": {
        "description": "OpenVPN exception for linking with OpenSSL",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "Qt-LGPL-exception-1.1": {
        "description": "Qt LGPL exception for static linking",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "WxWindows-exception-3.1": {
        "description": "wxWindows exception for library linking",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "PS-or-PDF-font-exception-20170817": {
        "description": "PS/PDF font exception — embedded fonts not copyleft",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Swift-exception": {
        "description": "Swift runtime exception",
        "reduces_risk_to": "low",
        "modifies_obligations": {"source_disclosure": False, "same_license": False},
    },
    "Universal-FOSS-exception-1.0": {
        "description": "Universal FOSS exception for combining with FOSS",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "389-exception": {
        "description": "389 Directory Server exception",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "i2p-gpl-java-exception": {
        "description": "I2P GPL Java exception for linking",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "Nokia-Qt-exception-1.1": {
        "description": "Nokia Qt exception for commercial use",
        "reduces_risk_to": "medium",
        "modifies_obligations": {"linking_exception": True},
    },
    "OCaml-LGPL-linking-exception": {
        "description": "OCaml LGPL exception for static linking",
        "reduces_risk_to": "low",
        "modifies_obligations": {"linking_exception": True, "source_disclosure": False},
    },
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def normalize_license(raw: str) -> str:
    """Normalize a license string to SPDX identifier."""
    if not raw:
        return "NOASSERTION"
    cleaned = raw.strip()
    # Direct match
    if cleaned in LICENSE_RISK:
        return cleaned
    # Alias lookup (case-insensitive)
    lower = cleaned.lower()
    if lower in _ALIASES:
        return _ALIASES[lower]
    # Case-insensitive match against known SPDX IDs
    for spdx_id in LICENSE_RISK:
        if spdx_id.lower() == lower:
            return spdx_id
    return cleaned


def classify_risk(license_id: str) -> str:
    """Classify a license by risk level. Returns high/medium/low/none/unknown."""
    normalized = normalize_license(license_id)
    return LICENSE_RISK.get(normalized, "unknown")


# ---------------------------------------------------------------------------
# SPDX Expression Parser
# ---------------------------------------------------------------------------

class SPDXExpressionParser:
    """Parse SPDX license expressions: OR, AND, WITH, parentheses.

    Grammar (simplified):
        expression := term (OR term)*
        term       := factor (AND factor)*
        factor     := simple_expr | '(' expression ')'
        simple_expr := license_id (WITH exception_id)?
    """

    _TOKEN_RE = re.compile(
        r"""
        \s*
        (?:
            (\()                         # open paren
            |(\))                        # close paren
            |\b(OR|AND|WITH)\b           # keyword
            |([\w][\w.\-+]*[\w+]?)       # license / exception identifier
        )
        \s*
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    def __init__(self, expression: str):
        self.expression = expression.strip()
        self.tokens: list[str] = []
        self.pos = 0
        self._tokenize()

    def _tokenize(self) -> None:
        pos = 0
        expr = self.expression
        while pos < len(expr):
            m = self._TOKEN_RE.match(expr, pos)
            if not m:
                # Skip unrecognized character
                pos += 1
                continue
            token = m.group(1) or m.group(2) or m.group(3) or m.group(4)
            if token:
                self.tokens.append(token)
            pos = m.end()

    def _peek(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _consume(self) -> str | None:
        tok = self._peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse(self) -> dict:
        """Parse expression and return structured result.

        Returns a dict with:
          - "type": "simple" | "or" | "and" | "with"
          - "license": str (for simple/with)
          - "exception": str (for with)
          - "children": list[dict] (for or/and)
        """
        if not self.tokens:
            return {"type": "simple", "license": "NOASSERTION"}
        result = self._parse_or()
        return result

    def _parse_or(self) -> dict:
        left = self._parse_and()
        children = [left]
        while self._peek() and self._peek().upper() == "OR":
            self._consume()
            children.append(self._parse_and())
        if len(children) == 1:
            return children[0]
        return {"type": "or", "children": children}

    def _parse_and(self) -> dict:
        left = self._parse_factor()
        children = [left]
        while self._peek() and self._peek().upper() == "AND":
            self._consume()
            children.append(self._parse_factor())
        if len(children) == 1:
            return children[0]
        return {"type": "and", "children": children}

    def _parse_factor(self) -> dict:
        tok = self._peek()
        if tok == "(":
            self._consume()
            result = self._parse_or()
            if self._peek() == ")":
                self._consume()
            return result
        return self._parse_simple()

    def _parse_simple(self) -> dict:
        license_id = self._consume()
        if license_id is None:
            return {"type": "simple", "license": "NOASSERTION"}
        # Normalize
        license_id = normalize_license(license_id)
        # Check for WITH exception
        if self._peek() and self._peek().upper() == "WITH":
            self._consume()
            exception_id = self._consume() or ""
            return {"type": "with", "license": license_id, "exception": exception_id}
        return {"type": "simple", "license": license_id}


def _collect_licenses_from_ast(ast: dict) -> list[dict]:
    """Flatten an SPDX parse tree into a list of license entries.

    Each entry: {"license": str, "exception": str|None}
    """
    results: list[dict] = []
    node_type = ast.get("type")

    if node_type == "simple":
        results.append({"license": ast["license"], "exception": None})
    elif node_type == "with":
        results.append({"license": ast["license"], "exception": ast.get("exception")})
    elif node_type in ("or", "and"):
        for child in ast.get("children", []):
            results.extend(_collect_licenses_from_ast(child))
    return results


def _best_risk_from_or(ast: dict) -> tuple[str, str]:
    """For an OR expression, pick the lowest-risk option.

    Returns (best_license_id, best_risk_level).
    """
    risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "unknown": 4}

    if ast["type"] == "or":
        best_license = "NOASSERTION"
        best_risk = "unknown"
        best_score = 999
        for child in ast.get("children", []):
            child_license, child_risk = _best_risk_from_or(child)
            score = risk_order.get(child_risk, 4)
            if score < best_score:
                best_score = score
                best_risk = child_risk
                best_license = child_license
        return best_license, best_risk
    elif ast["type"] == "with":
        lic = ast["license"]
        exc = ast.get("exception", "")
        risk = classify_risk(lic)
        # Apply exception risk reduction
        if exc and exc in SPDX_EXCEPTIONS:
            reduced = SPDX_EXCEPTIONS[exc].get("reduces_risk_to")
            if reduced:
                risk_order_val = {"none": 0, "low": 1, "medium": 2, "high": 3, "unknown": 4}
                if risk_order_val.get(reduced, 4) < risk_order_val.get(risk, 4):
                    risk = reduced
        return lic, risk
    elif ast["type"] == "and":
        # AND means all apply — take the *worst* risk
        worst_license = "NOASSERTION"
        worst_risk = "none"
        worst_score = -1
        for child in ast.get("children", []):
            child_license, child_risk = _best_risk_from_or(child)
            score = risk_order.get(child_risk, 4)
            if score > worst_score:
                worst_score = score
                worst_risk = child_risk
                worst_license = child_license
        return worst_license, worst_risk
    else:
        lic = ast.get("license", "NOASSERTION")
        return lic, classify_risk(lic)


# ---------------------------------------------------------------------------
# Main LicenseChecker class
# ---------------------------------------------------------------------------

class LicenseChecker:
    """Check dependency licenses against org-configurable policy.

    Supports:
      - License risk classification (200+ SPDX identifiers)
      - SPDX expression parsing (OR / AND / WITH)
      - License compatibility checking against project license
      - Obligation aggregation across all dependencies
      - Blocked license enforcement
    """

    def __init__(
        self,
        blocked_licenses: list[str] | None = None,
        project_license: str | None = None,
    ):
        self.blocked = set(blocked_licenses or _DEFAULT_BLOCKED)
        self.project_license = normalize_license(project_license) if project_license else None

    # ----- Core dependency check (enhanced) -----

    def check_dependencies(self, dependencies: list[dict]) -> list[dict]:
        """Check all dependencies for license compliance issues.

        Handles SPDX expressions (OR/AND/WITH), generates compatibility
        warnings, and includes obligation summaries.

        Returns findings compatible with SastFinding schema.
        """
        findings: list[dict] = []

        for dep in dependencies:
            raw_license = dep.get("license_id") or ""
            dep_name = dep.get("name", "unknown")
            dep_version = dep.get("version", "")
            manifest = dep.get("manifest_file", "")

            # ------ SPDX expression handling ------
            parsed = self.parse_spdx_expression(raw_license)
            effective_license = parsed.get("effective_license", "NOASSERTION")
            effective_risk = parsed.get("effective_risk", "unknown")
            is_compound = parsed.get("is_compound", False)

            # Normalize and store back
            if effective_license == "NOASSERTION" and not raw_license.strip():
                effective_risk = "medium"  # unknown/empty = medium risk
            dep["license_id"] = effective_license
            dep["license_risk"] = effective_risk
            dep["license_parsed"] = parsed

            # ------ Empty / unknown license ------
            if not raw_license.strip() or effective_license == "NOASSERTION":
                fp_raw = f"license.unknown|{dep_name}"
                findings.append({
                    "rule_id": "license.unknown",
                    "rule_source": "license",
                    "severity": "medium",
                    "confidence": "medium",
                    "title": f"Unknown license: {dep_name}",
                    "description": (
                        f"Dependency {dep_name}@{dep_version} has no license specified "
                        f"or the license could not be determined. This may pose legal risk."
                    ),
                    "message": f"{dep_name} has no declared license",
                    "file_path": manifest,
                    "line_start": 0,
                    "line_end": 0,
                    "code_snippet": f'"{dep_name}": "{dep_version}"',
                    "cwe_id": "CWE-1357",
                    "owasp_category": "A06:2021",
                    "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                    "obligations": {},
                })
                continue

            # ------ Blocked license check ------
            blocked_match = self._find_blocked_license(parsed)
            if blocked_match:
                fp_raw = f"license.blocked|{dep_name}|{blocked_match}"
                findings.append({
                    "rule_id": f"license.blocked.{blocked_match.lower()}",
                    "rule_source": "license",
                    "severity": "high",
                    "confidence": "high",
                    "title": f"Blocked license: {dep_name} uses {blocked_match}",
                    "description": (
                        f"Dependency {dep_name}@{dep_version} uses license {blocked_match} "
                        f"which is on the organization's blocked license list."
                        + (f" (from expression: {raw_license})" if is_compound else "")
                    ),
                    "message": f"{dep_name} has blocked license {blocked_match}",
                    "file_path": manifest,
                    "line_start": 0,
                    "line_end": 0,
                    "code_snippet": f'"{dep_name}": "{dep_version}"',
                    "cwe_id": "CWE-1357",
                    "owasp_category": "A06:2021",
                    "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                    "obligations": self._get_single_obligation(blocked_match),
                })

            # ------ High-risk license warning ------
            elif effective_risk == "high":
                fp_raw = f"license.high_risk|{dep_name}|{effective_license}"
                findings.append({
                    "rule_id": f"license.high_risk.{effective_license.lower()}",
                    "rule_source": "license",
                    "severity": "medium",
                    "confidence": "high",
                    "title": f"High-risk license: {dep_name} uses {effective_license}",
                    "description": (
                        f"Dependency {dep_name}@{dep_version} uses {effective_license}, "
                        f"a copyleft license that may require source disclosure."
                        + (f" (from expression: {raw_license})" if is_compound else "")
                    ),
                    "message": f"{dep_name} has high-risk license {effective_license}",
                    "file_path": manifest,
                    "line_start": 0,
                    "line_end": 0,
                    "code_snippet": f'"{dep_name}": "{dep_version}"',
                    "cwe_id": "CWE-1357",
                    "owasp_category": "A06:2021",
                    "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                    "obligations": self._get_single_obligation(effective_license),
                })

            # ------ Medium-risk license info ------
            elif effective_risk == "medium":
                fp_raw = f"license.medium_risk|{dep_name}|{effective_license}"
                findings.append({
                    "rule_id": f"license.medium_risk.{effective_license.lower()}",
                    "rule_source": "license",
                    "severity": "low",
                    "confidence": "high",
                    "title": f"Medium-risk license: {dep_name} uses {effective_license}",
                    "description": (
                        f"Dependency {dep_name}@{dep_version} uses {effective_license}, "
                        f"a weak copyleft license with file-level or conditional obligations."
                        + (f" (from expression: {raw_license})" if is_compound else "")
                    ),
                    "message": f"{dep_name} has medium-risk license {effective_license}",
                    "file_path": manifest,
                    "line_start": 0,
                    "line_end": 0,
                    "code_snippet": f'"{dep_name}": "{dep_version}"',
                    "cwe_id": "CWE-1357",
                    "owasp_category": "A06:2021",
                    "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                    "obligations": self._get_single_obligation(effective_license),
                })

            # ------ Compatibility check (if project license set) ------
            if self.project_license and effective_license != "NOASSERTION":
                compat = self._check_single_compatibility(self.project_license, effective_license)
                if compat is not None and not compat["compatible"]:
                    fp_raw = f"license.incompatible|{dep_name}|{self.project_license}|{effective_license}"
                    findings.append({
                        "rule_id": "license.incompatible",
                        "rule_source": "license",
                        "severity": "high",
                        "confidence": "medium",
                        "title": f"License incompatibility: {dep_name} ({effective_license}) vs project ({self.project_license})",
                        "description": (
                            f"Dependency {dep_name}@{dep_version} uses {effective_license} "
                            f"which may be incompatible with the project license {self.project_license}. "
                            f"Reason: {compat.get('reason', 'see compatibility matrix')}"
                        ),
                        "message": f"{dep_name} license {effective_license} incompatible with project {self.project_license}",
                        "file_path": manifest,
                        "line_start": 0,
                        "line_end": 0,
                        "code_snippet": f'"{dep_name}": "{dep_version}"',
                        "cwe_id": "CWE-1357",
                        "owasp_category": "A06:2021",
                        "fingerprint": hashlib.sha256(fp_raw.encode()).hexdigest()[:32],
                    })

        return findings

    # ----- License Compatibility -----

    def check_compatibility(
        self,
        project_license: str,
        dependencies: list[dict],
    ) -> list[dict]:
        """Check compatibility of all dependency licenses with the project license.

        Args:
            project_license: SPDX identifier of the project's license.
            dependencies: List of dicts with at least "name", "version", "license_id".

        Returns:
            List of compatibility warning dicts:
              {
                "dependency": str,
                "dependency_license": str,
                "project_license": str,
                "compatible": bool,
                "reason": str,
                "risk_if_used": str,
              }
        """
        proj = normalize_license(project_license)
        warnings: list[dict] = []

        for dep in dependencies:
            raw = dep.get("license_id", "")
            dep_name = dep.get("name", "unknown")
            dep_version = dep.get("version", "")

            # Parse SPDX expression — for OR expressions we check each option
            parsed_ast = SPDXExpressionParser(raw).parse() if raw.strip() else None
            if not parsed_ast:
                warnings.append({
                    "dependency": f"{dep_name}@{dep_version}",
                    "dependency_license": "NOASSERTION",
                    "project_license": proj,
                    "compatible": False,
                    "reason": "No license declared — compatibility unknown",
                    "risk_if_used": "unknown",
                })
                continue

            # Collect all licenses from expression
            licenses = _collect_licenses_from_ast(parsed_ast)
            has_compatible_option = False
            all_results: list[dict] = []

            for lic_entry in licenses:
                dep_lic = normalize_license(lic_entry["license"])
                compat = self._check_single_compatibility(proj, dep_lic)
                if compat:
                    all_results.append(compat)
                    if compat["compatible"]:
                        has_compatible_option = True
                else:
                    all_results.append({
                        "compatible": True,
                        "reason": "No specific incompatibility known",
                        "risk_if_used": classify_risk(dep_lic),
                    })
                    has_compatible_option = True

            # For OR expressions, only warn if NO option is compatible
            is_or = parsed_ast.get("type") == "or"
            if is_or and has_compatible_option:
                # At least one choice is compatible
                best_option = min(
                    all_results,
                    key=lambda r: (not r["compatible"], {"none": 0, "low": 1, "medium": 2, "high": 3, "unknown": 4}.get(r.get("risk_if_used", "unknown"), 4)),
                )
                if not best_option["compatible"]:
                    warnings.append({
                        "dependency": f"{dep_name}@{dep_version}",
                        "dependency_license": raw,
                        "project_license": proj,
                        "compatible": False,
                        "reason": "No compatible license option in OR expression",
                        "risk_if_used": "high",
                    })
            elif not has_compatible_option:
                reasons = [r.get("reason", "") for r in all_results if not r["compatible"]]
                warnings.append({
                    "dependency": f"{dep_name}@{dep_version}",
                    "dependency_license": raw,
                    "project_license": proj,
                    "compatible": False,
                    "reason": "; ".join(reasons) if reasons else "License incompatible with project license",
                    "risk_if_used": "high",
                })
            else:
                # AND expression or simple — check if any is incompatible
                for res in all_results:
                    if not res["compatible"]:
                        warnings.append({
                            "dependency": f"{dep_name}@{dep_version}",
                            "dependency_license": raw,
                            "project_license": proj,
                            "compatible": False,
                            "reason": res.get("reason", "License incompatible"),
                            "risk_if_used": res.get("risk_if_used", "high"),
                        })
                        break

        return warnings

    # ----- Obligation Tracking -----

    def get_obligations(self, dependencies: list[dict]) -> dict:
        """Aggregate license obligations across all dependencies.

        Args:
            dependencies: List of dicts with at least "license_id".

        Returns:
            {
                "summary": {
                    "attribution": bool,  # any dep requires it
                    "source_disclosure": bool,
                    "notice_file": bool,
                    "state_changes": bool,
                    "network_use_disclosure": bool,
                    "no_endorsement": bool,
                    "linking_exception": bool,
                    "patent_grant": bool,
                    "patent_retaliation": bool,
                    "rename_required": bool,
                    "same_license": bool,
                    "file_level_copyleft": bool,
                },
                "per_license": {
                    "<license_id>": {
                        "obligations": dict,
                        "dependencies": [str],
                    }
                },
                "action_items": [str],  # human-readable action items
            }
        """
        all_obligation_keys = {
            "attribution", "source_disclosure", "notice_file", "state_changes",
            "network_use_disclosure", "no_endorsement", "linking_exception",
            "patent_grant", "patent_retaliation", "rename_required",
            "same_license", "file_level_copyleft", "trademark_restriction",
        }
        summary: dict[str, bool] = {k: False for k in all_obligation_keys}
        per_license: dict[str, dict] = {}

        for dep in dependencies:
            raw = dep.get("license_id", "")
            dep_name = dep.get("name", "unknown")

            # Parse SPDX expression
            if raw.strip():
                parsed_ast = SPDXExpressionParser(raw).parse()
                licenses = _collect_licenses_from_ast(parsed_ast)
            else:
                licenses = [{"license": "NOASSERTION", "exception": None}]

            for lic_entry in licenses:
                lic_id = normalize_license(lic_entry["license"])
                exception_id = lic_entry.get("exception")

                if lic_id == "NOASSERTION":
                    continue

                oblig = OBLIGATIONS.get(lic_id, {})

                # Apply exception modifications
                if exception_id and exception_id in SPDX_EXCEPTIONS:
                    oblig = dict(oblig)  # copy
                    mods = SPDX_EXCEPTIONS[exception_id].get("modifies_obligations", {})
                    oblig.update(mods)

                # Track per-license
                display_id = f"{lic_id} WITH {exception_id}" if exception_id else lic_id
                if display_id not in per_license:
                    per_license[display_id] = {"obligations": oblig, "dependencies": []}
                per_license[display_id]["dependencies"].append(dep_name)

                # Merge into summary
                for key, val in oblig.items():
                    if val and key in summary:
                        summary[key] = True

        # Generate human-readable action items
        action_items: list[str] = []
        if summary.get("attribution"):
            attr_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("attribution")]
            action_items.append(
                f"ATTRIBUTION REQUIRED: Include copyright/license notices for: {', '.join(attr_licenses)}"
            )
        if summary.get("source_disclosure"):
            src_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("source_disclosure")]
            action_items.append(
                f"SOURCE DISCLOSURE REQUIRED: Provide/offer source code for components under: {', '.join(src_licenses)}"
            )
        if summary.get("notice_file"):
            notice_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("notice_file")]
            action_items.append(
                f"NOTICE FILE REQUIRED: Include a NOTICE file with attributions for: {', '.join(notice_licenses)}"
            )
        if summary.get("state_changes"):
            sc_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("state_changes")]
            action_items.append(
                f"STATE CHANGES: Document modifications to files under: {', '.join(sc_licenses)}"
            )
        if summary.get("network_use_disclosure"):
            net_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("network_use_disclosure")]
            action_items.append(
                f"NETWORK USE DISCLOSURE: Source must be available to network users for: {', '.join(net_licenses)}"
            )
        if summary.get("same_license"):
            sl_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("same_license")]
            action_items.append(
                f"SAME LICENSE: Derivatives must remain under same license for: {', '.join(sl_licenses)}"
            )
        if summary.get("no_endorsement"):
            ne_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("no_endorsement")]
            action_items.append(
                f"NO ENDORSEMENT: Do not use author names for endorsement. Applies to: {', '.join(ne_licenses)}"
            )
        if summary.get("rename_required"):
            rn_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("rename_required")]
            action_items.append(
                f"RENAME REQUIRED: Forks/modifications must use different name for: {', '.join(rn_licenses)}"
            )
        if summary.get("patent_retaliation"):
            pr_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("patent_retaliation")]
            action_items.append(
                f"PATENT RETALIATION: License terminates if you initiate patent litigation. Applies to: {', '.join(pr_licenses)}"
            )
        if summary.get("linking_exception"):
            le_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("linking_exception")]
            action_items.append(
                f"LINKING EXCEPTION: Dynamic linking generally OK; static linking may trigger copyleft for: {', '.join(le_licenses)}"
            )
        if summary.get("trademark_restriction"):
            tr_licenses = [lid for lid, info in per_license.items() if info["obligations"].get("trademark_restriction")]
            action_items.append(
                f"TRADEMARK RESTRICTION: Specific trademark use restrictions for: {', '.join(tr_licenses)}"
            )

        return {
            "summary": summary,
            "per_license": per_license,
            "action_items": action_items,
        }

    # ----- SPDX Expression Parsing -----

    def parse_spdx_expression(self, expression: str) -> dict:
        """Parse an SPDX license expression and return risk assessment.

        Handles:
          - Simple: "MIT"
          - OR:     "MIT OR Apache-2.0" (pick most permissive)
          - AND:    "MIT AND BSD-3-Clause" (both apply, take worst risk)
          - WITH:   "GPL-2.0-only WITH Classpath-exception-2.0" (apply exception)
          - Nested: "(MIT OR Apache-2.0) AND BSD-3-Clause"

        Returns:
            {
                "expression": str,        # original expression
                "is_compound": bool,       # True if OR/AND/WITH present
                "ast": dict,              # parsed abstract syntax tree
                "effective_license": str, # best/effective license ID
                "effective_risk": str,    # risk level of effective license
                "all_licenses": [         # all licenses in expression
                    {"license": str, "exception": str|None, "risk": str}
                ],
                "exceptions_applied": [str],  # list of WITH exceptions
            }
        """
        if not expression or not expression.strip():
            return {
                "expression": expression or "",
                "is_compound": False,
                "ast": {"type": "simple", "license": "NOASSERTION"},
                "effective_license": "NOASSERTION",
                "effective_risk": "unknown",
                "all_licenses": [],
                "exceptions_applied": [],
            }

        # Check if it's a compound expression
        has_or = bool(re.search(r'\bOR\b', expression, re.IGNORECASE))
        has_and = bool(re.search(r'\bAND\b', expression, re.IGNORECASE))
        has_with = bool(re.search(r'\bWITH\b', expression, re.IGNORECASE))
        is_compound = has_or or has_and or has_with

        # For simple expressions, fast path
        if not is_compound:
            normalized = normalize_license(expression)
            risk = classify_risk(normalized)
            return {
                "expression": expression,
                "is_compound": False,
                "ast": {"type": "simple", "license": normalized},
                "effective_license": normalized,
                "effective_risk": risk,
                "all_licenses": [{"license": normalized, "exception": None, "risk": risk}],
                "exceptions_applied": [],
            }

        # Parse compound expression
        parser = SPDXExpressionParser(expression)
        ast = parser.parse()

        # Collect all licenses
        flat_licenses = _collect_licenses_from_ast(ast)
        all_licenses_info: list[dict] = []
        exceptions_applied: list[str] = []

        for entry in flat_licenses:
            lic = normalize_license(entry["license"])
            exc = entry.get("exception")
            risk = classify_risk(lic)
            # Apply exception risk reduction
            if exc:
                exceptions_applied.append(exc)
                if exc in SPDX_EXCEPTIONS:
                    reduced = SPDX_EXCEPTIONS[exc].get("reduces_risk_to")
                    if reduced:
                        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "unknown": 4}
                        if risk_order.get(reduced, 4) < risk_order.get(risk, 4):
                            risk = reduced
            all_licenses_info.append({"license": lic, "exception": exc, "risk": risk})

        # Determine effective license and risk
        effective_license, effective_risk = _best_risk_from_or(ast)

        return {
            "expression": expression,
            "is_compound": is_compound,
            "ast": ast,
            "effective_license": effective_license,
            "effective_risk": effective_risk,
            "all_licenses": all_licenses_info,
            "exceptions_applied": exceptions_applied,
        }

    # ----- Private helpers -----

    def _find_blocked_license(self, parsed: dict) -> str | None:
        """Check if any license in a parsed SPDX result is blocked.

        For OR expressions, if at least one non-blocked option exists,
        we do NOT flag it as blocked (user can choose the non-blocked option).
        For AND expressions, if any component is blocked, the whole thing is blocked.
        """
        all_lics = parsed.get("all_licenses", [])
        if not all_lics:
            return None

        ast = parsed.get("ast", {})

        # OR expression: only blocked if ALL options are blocked
        if ast.get("type") == "or":
            blocked_found = []
            has_non_blocked = False
            for lic_info in all_lics:
                lic = normalize_license(lic_info["license"])
                if lic in self.blocked:
                    blocked_found.append(lic)
                else:
                    has_non_blocked = True
            if has_non_blocked:
                return None  # at least one option is OK
            return blocked_found[0] if blocked_found else None

        # AND or simple: any blocked = blocked
        for lic_info in all_lics:
            lic = normalize_license(lic_info["license"])
            if lic in self.blocked:
                return lic
        return None

    def _check_single_compatibility(
        self,
        project_license: str,
        dep_license: str,
    ) -> dict | None:
        """Check a single license pair for compatibility.

        Returns dict with "compatible", "reason", "risk_if_used" or None if unknown.
        """
        proj = normalize_license(project_license)
        dep = normalize_license(dep_license)

        # Same license is always compatible
        if proj == dep:
            return {
                "compatible": True,
                "reason": "Same license",
                "risk_if_used": classify_risk(dep),
            }

        # Check explicit matrix
        key = (proj, dep)
        if key in COMPATIBILITY_MATRIX:
            is_compat = COMPATIBILITY_MATRIX[key]
            if is_compat:
                reason = "Compatible per license compatibility matrix"
                # Special caveat for permissive project + copyleft dep
                if dep in _STRONG_COPYLEFT and proj in _PERMISSIVE_LICENSES:
                    reason = (
                        f"Compatible, but {dep} terms will propagate — "
                        f"your project effectively becomes {dep} for distribution"
                    )
                elif dep in _LGPL_FAMILY and proj == "proprietary":
                    reason = f"Compatible via dynamic linking only — static linking would require {dep} compliance"
            else:
                reason = f"{proj} is incompatible with {dep}"
                # Add specific well-known reasons
                if proj in _GPL2_FAMILY and dep == "Apache-2.0":
                    reason = "GPL-2.0 and Apache-2.0 have incompatible patent clauses"
                elif dep == "Apache-2.0" and proj in _GPL2_FAMILY:
                    reason = "GPL-2.0 and Apache-2.0 have incompatible patent clauses"
                elif proj == "proprietary" and dep in _STRONG_COPYLEFT:
                    reason = f"Proprietary projects cannot use {dep} (strong copyleft requires source disclosure)"
                elif proj == "proprietary" and dep in ("CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0"):
                    reason = f"Proprietary projects cannot use {dep} (share-alike/non-commercial restriction)"

            return {
                "compatible": is_compat,
                "reason": reason,
                "risk_if_used": classify_risk(dep),
            }

        # Heuristic: permissive dep is almost always compatible
        dep_risk = classify_risk(dep)
        if dep_risk in ("low", "none"):
            return {
                "compatible": True,
                "reason": f"{dep} is permissive — generally compatible with any project license",
                "risk_if_used": dep_risk,
            }

        # Unknown pair — return None to indicate we have no data
        return None

    def _get_single_obligation(self, license_id: str) -> dict:
        """Get obligations for a single license, returning empty dict if unknown."""
        normalized = normalize_license(license_id)
        return OBLIGATIONS.get(normalized, {})
