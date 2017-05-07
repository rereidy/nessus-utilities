# nessus-utilities

This repository contains Nessus tools I have created during my time as a security engineer.

1.  yane (Yet another Nessus Exporter) - Python script to export Nessus reports (CSV and .nessus formats)

    This program is meant to automate the process of exporting Nessus scans
    by accessing the Nessus server and programtically performing the actions
    a human user would take to perform the export function.

2. nasl_cfg_rpt - Python script to print inventory of .nasl files on the Nessus server.

    Prints an inventory of .nasl files and their properties.  NASL file properties in the report include the following:
    
     1.  script_id
     2.  script_family
     3.  script_version
     4.  script_cvs_date
     5.  script_osvdb_id
     6.  script_bugtrack_id
     7.  script_cve_id
     8.  script_name
     9.  script_summary
    10.  script_copyright
    
    The output is a CSV file.
    
   
