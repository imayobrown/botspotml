#!/usr/bin/env

import csv
import os
import sys

src_ip_column    = 'Src IP'
src_port_column  = 'Src Port'
dest_ip_column   = 'Dst IP'
dest_port_column = 'Dst Port'
label_column     = 'Label'

# TODO: figure out if following are actually detectable
# NSIS_BOTNET_COUNTER
# SMTP_SPAM_BOTNET_COUNTER
# UDP_STORM_BOTNET_COUNTER

IRC_BOTNET_COUNTER = 0
NERIS_BOTNET_COUNTER = 0
RBOT_BOTNET_COUNTER = 0
MENTI_BOTNET_COUNTER = 0
SOGOU_BOTNET_COUNTER = 0
MURLO_BOTNET_COUNTER = 0
VIRUT_BOTNET_COUNTER = 0
NSIS_BOTNET_COUNTER = 0
ZEUS_BOTNET_COUNTER = 0
SMTP_SPAM_BOTNET_COUNTER = 0
UDP_STORM_BOTNET_COUNTER = 0
TBOT_BOTNET_COUNTER = 0
ZERO_ACCESS_BOTNET_COUNTER = 0
WEASEL_BOTNET_COUNTER = 0
SMOKE_BOT_BOTNET_COUNTER = 0
ISCX_IRC_BOTNET_COUNTER = 0
OSX_TROJAN_BOTNET_COUNTER = 0


def reset_botnet_flow_counts():

    IRC_BOTNET_COUNTER = 0
    NERIS_BOTNET_COUNTER = 0
    RBOT_BOTNET_COUNTER = 0
    MENTI_BOTNET_COUNTER = 0
    SOGOU_BOTNET_COUNTER = 0
    MURLO_BOTNET_COUNTER = 0
    VIRUT_BOTNET_COUNTER = 0
    NSIS_BOTNET_COUNTER = 0
    ZEUS_BOTNET_COUNTER = 0
    SMTP_SPAM_BOTNET_COUNTER = 0
    UDP_STORM_BOTNET_COUNTER = 0
    TBOT_BOTNET_COUNTER = 0
    ZERO_ACCESS_BOTNET_COUNTER = 0
    WEASEL_BOTNET_COUNTER = 0
    SMOKE_BOT_BOTNET_COUNTER = 0
    ISCX_IRC_BOTNET_COUNTER = 0
    OSX_TROJAN_BOTNET_COUNTER = 0


def report_botnet_flow_counts():

    print("Botnet Flow Counts:")
    print("    IRC_BOTNET_COUNTER: {}".format(IRC_BOTNET_COUNTER))
    print("    NERIS_BOTNET_COUNTER: {}".format(NERIS_BOTNET_COUNTER))
    print("    RBOT_BOTNET_COUNTER: {}".format(RBOT_BOTNET_COUNTER))
    print("    MENTI_BOTNET_COUNTER: {}".format(MENTI_BOTNET_COUNTER))
    print("    SOGOU_BOTNET_COUNTER: {}".format(SOGOU_BOTNET_COUNTER))
    print("    MURLO_BOTNET_COUNTER: {}".format(MURLO_BOTNET_COUNTER))
    print("    VIRUT_BOTNET_COUNTER: {}".format(VIRUT_BOTNET_COUNTER))
    print("    NSIS_BOTNET_COUNTER: {}".format(NSIS_BOTNET_COUNTER))
    print("    ZEUS_BOTNET_COUNTER: {}".format(ZEUS_BOTNET_COUNTER))
    print("    SMTP_SPAM_BOTNET_COUNTER: {}".format(SMTP_SPAM_BOTNET_COUNTER))
    print("    UDP_STORM_BOTNET_COUNTER: {}".format(UDP_STORM_BOTNET_COUNTER))
    print("    TBOT_BOTNET_COUNTER: {}".format(TBOT_BOTNET_COUNTER))
    print("    ZERO_ACCESS_BOTNET_COUNTER: {}".format(ZERO_ACCESS_BOTNET_COUNTER))
    print("    WEASEL_BOTNET_COUNTER: {}".format(WEASEL_BOTNET_COUNTER))
    print("    SMOKE_BOT_BOTNET_COUNTER: {}".format(SMOKE_BOT_BOTNET_COUNTER))
    print("    ISCX_IRC_BOTNET_COUNTER: {}".format(ISCX_IRC_BOTNET_COUNTER))
    print("    OSX_TROJAN_BOTNET_COUNTER: {}".format(OSX_TROJAN_BOTNET_COUNTER))


def is_irc_botnet_flow(flow):

    irc_botnet_ip_pairs = [
        {"src_ip": "192.168.2.112", "dest_ip": "131.202.243.84"},
        {"src_ip": "192.168.5.122", "dest_ip": "198.164.30.2"},
        {"src_ip": "192.168.2.110", "dest_ip": "192.168.5.122"},
        {"src_ip": "192.168.4.118", "dest_ip": "192.168.5.122"},
        {"src_ip": "192.168.2.113", "dest_ip": "192.168.5.122"},
        {"src_ip": "192.168.1.103", "dest_ip": "192.168.5.122"},
        {"src_ip": "192.168.4.120", "dest_ip": "192.168.5.122"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.2.110"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.4.120"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.1.103"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.2.113"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.4.118"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.2.109"},
        {"src_ip": "192.168.2.112", "dest_ip": "192.168.2.105"},
        {"src_ip": "192.168.1.105", "dest_ip": "192.168.5.122"}
    ]

    is_botnet_flow = False

    if {"src_ip": flow[src_ip_column], "dest_ip": flow[dest_ip_column]} in irc_botnet_ip_pairs:

        is_botnet_flow = True

        global IRC_BOTNET_COUNTER

        IRC_BOTNET_COUNTER += 1

    return is_botnet_flow


def is_botnet_flow(flow, ips):

    botnet_flow = False

    src_ip_in_ips = flow[src_ip_column] in ips

    dest_ip_in_ips = flow[dest_ip_column] in ips

    if src_ip_in_ips or dest_ip_in_ips:

        botnet_flow = True

    return botnet_flow

def is_neris_botnet_flow(flow):

    neris_botnet_ips = [
        "147.32.84.180"
    ]

    botnet_flow = is_botnet_flow(flow, neris_botnet_ips)

    if botnet_flow:

        global NERIS_BOTNET_COUNTER

        NERIS_BOTNET_COUNTER += 1

    return botnet_flow


def is_rbot_botnet_flow(flow):

    rbot_botnet_ips = [
        "147.32.84.170"
    ]

    botnet_flow = is_botnet_flow(flow, rbot_botnet_ips)

    if botnet_flow:

        global RBOT_BOTNET_COUNTER

        RBOT_BOTNET_COUNTER += 1

    return botnet_flow


def is_menti_botnet_flow(flow):

    menti_botnet_ips = [
        "147.32.84.150"
    ]

    botnet_flow = is_botnet_flow(flow, menti_botnet_ips)

    if botnet_flow:

        global MENTI_BOTNET_COUNTER

        MENTI_BOTNET_COUNTER += 1

    return botnet_flow


def is_sogou_botnet_flow(flow):

    sogou_botnet_ips = [
        "147.32.84.140"
    ]

    botnet_flow = is_botnet_flow(flow, sogou_botnet_ips)

    if botnet_flow:

        global SOGOU_BOTNET_COUNTER

        SOGOU_BOTNET_COUNTER += 1

    return botnet_flow


def is_murlo_botnet_flow(flow):

    murlo_botnet_ips = [
        "147.32.84.130"
    ]

    botnet_flow = is_botnet_flow(flow, murlo_botnet_ips)

    if botnet_flow:

        global MURLO_BOTNET_COUNTER

        MURLO_BOTNET_COUNTER += 1

    return botnet_flow


def is_virut_botnet_flow(flow):

    virut_botnet_ips = [
        "147.32.84.160"
    ]

    botnet_flow = is_botnet_flow(flow, virut_botnet_ips)

    if botnet_flow:

        global VIRUT_BOTNET_COUNTER

        VIRUT_BOTNET_COUNTER += 1

    return botnet_flow


def is_blackhole1_botnet_flow(flow):

    ircbot_blackhole1_botnet_ips = [
        "10.0.2.15"
    ]

    botnet_flow = is_botnet_flow(flow, ircbot_blackhole1_botnet_ips)

    if botnet_flow:

        global ISCX_IRC_BOTNET_COUNTER

        ISCX_IRC_BOTNET_COUNTER += 1

    return botnet_flow


def is_blackhole2_botnet_flow(flow):

    blackhole2_botnet_ips = [
        "192.168.106.141"
    ]

    botnet_flow = is_botnet_flow(flow, blackhole2_botnet_ips)

    if botnet_flow:

        global ISCX_IRC_BOTNET_COUNTER

        ISCX_IRC_BOTNET_COUNTER += 1

    return botnet_flow


def is_blackhole3_botnet_flow(flow):

    blackhole3_botnet_ips = [
        "192.168.106.131"
    ]

    botnet_flow = is_botnet_flow(flow, blackhole3_botnet_ips)

    if botnet_flow:

        global ISCX_IRC_BOTNET_COUNTER

        ISCX_IRC_BOTNET_COUNTER += 1

    return botnet_flow


def is_tbot_botnet_flow(flow):

    tbot_botnet_ips = [
        "172.16.253.130",
        "172.16.253.131",
        "172.16.253.129",
        "172.16.253.240"
    ]

    botnet_flow = is_botnet_flow(flow, tbot_botnet_ips)

    if botnet_flow:

        global TBOT_BOTNET_COUNTER

        TBOT_BOTNET_COUNTER += 1

    return botnet_flow


def is_weasel_botmaster_flow(flow):

    weasel_botmaster_ip = [
        "74.78.117.238"
    ]

    botnet_flow = is_botnet_flow(flow, weasel_botmaster_ip)

    if botnet_flow:

        global WEASEL_BOTNET_COUNTER

        WEASEL_BOTNET_COUNTER += 1

    return botnet_flow


def is_weasel_botnet_flow(flow):

    weasel_bot_ip = [
        "158.65.110.24"
    ]

    botnet_flow = is_botnet_flow(flow, weasel_bot_ip)

    if botnet_flow:

        global WEASEL_BOTNET_COUNTER

        WEASEL_BOTNET_COUNTER += 1

    return botnet_flow


def is_zeus_botnet_flow(flow):

    zeus_botnet_ips = [
        "192.168.3.35",
        "192.168.3.25",
        "192.168.3.65",
        "172.29.0.116"
    ]

    botnet_flow = is_botnet_flow(flow, zeus_botnet_ips)

    if botnet_flow:

        global ZEUS_BOTNET_COUNTER

        ZEUS_BOTNET_COUNTER += 1

    return botnet_flow


def is_osx_trojan_botnet_flow(flow):

    osx_trojan_botnet_ips = [
        "172.29.0.109",
    ]

    botnet_flow = is_botnet_flow(flow, osx_trojan_botnet_ips)

    if botnet_flow:

        global OSX_TROJAN_BOTNET_COUNTER

        OSX_TROJAN_BOTNET_COUNTER += 1

    return botnet_flow


def is_zero_access_botnet_flow(flow):

    zero_access_botnet_ips = [
        "172.16.253.132",
        "192.168.248.165"
    ]

    botnet_flow = is_botnet_flow(flow, zero_access_botnet_ips)

    if botnet_flow:

        global ZERO_ACCESS_BOTNET_COUNTER

        ZERO_ACCESS_BOTNET_COUNTER += 1

    return botnet_flow


def is_smoke_bot_botnet_flow(flow):

    smoke_bot_ips = [
        "10.37.130.4"
    ]

    botnet_flow = is_botnet_flow(flow, smoke_bot_ips)

    if botnet_flow:

        global SMOKE_BOT_BOTNET_COUNTER

        SMOKE_BOT_BOTNET_COUNTER += 1

    return botnet_flow


def is_any_botnet_flow(flow):

    botnet_flow = any([
        is_irc_botnet_flow(flow),
        is_neris_botnet_flow(flow),
        is_rbot_botnet_flow(flow),
        is_menti_botnet_flow(flow),
        is_sogou_botnet_flow(flow),
        is_murlo_botnet_flow(flow),
        is_virut_botnet_flow(flow),
        is_blackhole1_botnet_flow(flow),
        is_blackhole2_botnet_flow(flow),
        is_blackhole3_botnet_flow(flow),
        is_tbot_botnet_flow(flow),
        is_weasel_botmaster_flow(flow),
        is_weasel_botnet_flow(flow),
        is_zeus_botnet_flow(flow),
        is_osx_trojan_botnet_flow(flow),
        is_zero_access_botnet_flow(flow),
        is_smoke_bot_botnet_flow(flow)
    ])

    return botnet_flow


def label_flows(flow_csv_file):

    flows = csv.DictReader(flow_csv_file)

    labeled_flows = []

    botnet_flows = 0

    notbotnet_flows = 0

    for flow in flows:

        botnet_flow = is_any_botnet_flow(flow)

        labeled_flow = flow

        if botnet_flow:

            labeled_flow[label_column] = "botnet"

            botnet_flows += 1

        else:

            labeled_flow[label_column] = "notbotnet"

            notbotnet_flows += 1

        labeled_flows.append(labeled_flow)

    print("Botnet flows: {}".format(botnet_flows))

    print("Notbotnet flows: {}".format(notbotnet_flows))

    return flows.fieldnames, labeled_flows


def write_labeled_csv_flow_file(labeled_flows, labeled_flows_fieldnames, labeled_flows_csv_file_path):

    with open(labeled_flows_csv_file_path, 'w') as labeled_flows_csv_file:

        writer = csv.DictWriter(labeled_flows_csv_file, fieldnames=labeled_flows_fieldnames)

        for labeled_flow in labeled_flows:

            writer.writerow(labeled_flow)


training_flows_path = sys.argv[1]
testing_flows_path  = sys.argv[2]

labeled_training_flows_path = sys.argv[3]
labeled_testing_flows_path  = sys.argv[4]

# TRAINING DATASET LABELING

print("Reading training data set flow from {}...".format(training_flows_path))

with open(training_flows_path, 'r') as training_flow_csv_file:

    print("Labeling training flows...")

    training_flows_fieldnames, labeled_training_flows = label_flows(training_flow_csv_file)

print("Writing labeled training flows to file {}...".format(labeled_training_flows_path))

write_labeled_csv_flow_file(labeled_training_flows, training_flows_fieldnames, labeled_training_flows_path)

report_botnet_flow_counts()

reset_botnet_flow_counts()

# TESTING DATASET LABELING

print("Reading testing data set flow from {}...".format(testing_flows_path))

with open(testing_flows_path) as testing_flow_csv_file:

    print("Labeling testing flows...")

    testing_flows_fieldnames, labeled_testing_flows = label_flows(testing_flow_csv_file)

print("Writing labeled testing flows to file {}...".format(labeled_testing_flows_path))

write_labeled_csv_flow_file(labeled_testing_flows, testing_flows_fieldnames, labeled_testing_flows_path)

report_botnet_flow_counts()
