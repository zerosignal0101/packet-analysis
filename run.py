import os
import argparse
import packet_analysis.preprocess.extract_to_csv as extract_to_csv
import packet_analysis.preprocess.alignment as alignment
import packet_analysis.analysis.cluster as cluster
import time


# parse command-line arguments
def parse_args(args=None, namespace=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        nargs=2,
        required=True,
        help="path to the input file (pcap or csv), former is the file in production, latter is in back"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        required=False,
        help="path to the output folder | default: ./results",
    )
    parser.add_argument(
        "-method",
        "--method",
        type=str,
        required=False,
        default='all',
        help="preprocess, align or analysis | default: all",
    )
    return parser.parse_args(args=args, namespace=namespace)


if __name__ == '__main__':
    # get timestamp
    time_now = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
    print(time_now)

    # parse commands
    cmd = parse_args()
    file_input = cmd.input
    folder_output = cmd.output

    # remove ' in the args
    file_input = [item.strip("'") for item in file_input]

    # check file input validity
    if not file_input[0].endswith('.pcap') and not file_input[0].endswith('.csv'):
        print(f"Error: {file_input[0]} is not a valid file format.")
        exit(1)
    if not file_input[1].endswith('.pcap') and not file_input[1].endswith('.csv'):
        print(f"Error: {file_input[1]} is not a valid file format.")
        exit(1)

    # Variables
    csv_production_output = ''
    csv_back_output = ''
    csv_aligned_output = ''

    # check if input file exists
    if not os.path.exists(file_input[0]) or not os.path.exists(file_input[1]):
        print(f"Error: {file_input} does not exist.")
        exit(1)

    # check if output folder exists
    if folder_output is None:
        folder_output = os.path.join(os.getcwd(), f"results")
    if not os.path.exists(folder_output):
        os.makedirs(folder_output)

    # preprocess data
    if cmd.method == 'preprocess' or cmd.method == 'all':
        pcap_input = file_input
        csv_production_output = os.path.join(folder_output, "extracted_production_data.csv")
        csv_back_output = os.path.join(folder_output, "extracted_back_data.csv")
        extract_to_csv.preprocess_data(pcap_input[0], csv_production_output)
        extract_to_csv.preprocess_data(pcap_input[1], csv_back_output)

    # alignment
    if cmd.method == 'align' or cmd.method == 'all':
        if csv_production_output == '' and csv_back_output == '':
            csv_aligned_output = alignment.alignment_path_query(file_input[0], file_input[1], folder_output)
        else:
            csv_aligned_output = alignment.alignment_path_query(csv_production_output, csv_back_output, folder_output)

    # analyze data
    if cmd.method == 'analysis' or cmd.method == 'all':
        if csv_production_output == '' and csv_back_output == '':
            cluster.analysis(file_input[0], os.path.join(folder_output, 'production'))
            cluster.analysis(file_input[1], os.path.join(folder_output, 'back'))
        else:
            cluster.analysis(csv_production_output, os.path.join(folder_output, 'production'))
            cluster.analysis(csv_back_output, os.path.join(folder_output, 'back'))
