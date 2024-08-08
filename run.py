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
        "-ip",
        "--input-production",
        type=str,
        required=True,
        help="path to the input files (pcap or csv format), the file in production"
    )
    parser.add_argument(
        "-ib",
        "--input-back",
        type=str,
        required=True,
        help="path to the input files (pcap or csv format), the file in back"
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
    production_inputs = cmd.input_production
    back_inputs = cmd.input_back
    folder_output = cmd.output

    # Variables
    csv_production_output = ''
    csv_back_output = ''
    csv_aligned_output = ''

    # transfrom the production input files to list
    production_inputs = production_inputs.split(',')

    # transfrom the back input files to list
    back_inputs = back_inputs.split(',')

    # # test pause
    # print(production_inputs)
    # print(back_inputs)
    # print("pause")
    # exit(1)

    # check if the production input files from the list 'production_inputs' exist or not
    for file in production_inputs:
        if not os.path.exists(file):
            print(f"File {file} does not exist.")
            exit(1)

    # check if the back input files from the list 'production_inputs' exist or not
    for file in back_inputs:
        if not os.path.exists(file):
            print(f"File {file} does not exist.")
            exit(1)

    # check if the production input files are pcap or csv
    for file in production_inputs:
        if not file.endswith('.pcap') and not file.endswith('.csv'):
            print(f"File {file} in production field is not a pcap or csv file.")
            exit(1)

    # check if the back input files are pcap or csv
    for file in back_inputs:
        if not file.endswith('.pcap') and not file.endswith('.csv'):
            print(f"File {file} in back field is not a pcap or csv file.")
            exit(1)

    # check if output folder exists
    if folder_output is None:
        folder_output = os.path.join(os.getcwd(), f"results")
    if not os.path.exists(folder_output):
        os.makedirs(folder_output)

    # preprocess data
    if cmd.method == 'preprocess' or cmd.method == 'all':
        csv_production_output = os.path.join(folder_output, "extracted_production_data.csv")
        csv_back_output = os.path.join(folder_output, "extracted_back_data.csv")
        extract_to_csv.preprocess_data(production_inputs, csv_production_output)
        extract_to_csv.preprocess_data(back_inputs, csv_back_output)

    # alignment
    if cmd.method == 'align' or cmd.method == 'all':
        if csv_production_output == '' and csv_back_output == '':
            csv_aligned_output = alignment.alignment_path_query(production_inputs[0], back_inputs[0], folder_output)
        else:
            csv_aligned_output = alignment.alignment_path_query(csv_production_output, csv_back_output, folder_output)

    # analyze data
    if cmd.method == 'analysis' or cmd.method == 'all':
        if csv_production_output == '' and csv_back_output == '':
            cluster.analysis(production_inputs[0], os.path.join(folder_output, 'production'))
            cluster.analysis(back_inputs[0], os.path.join(folder_output, 'back'))
        else:
            cluster.analysis(csv_production_output, os.path.join(folder_output, 'production'))
            cluster.analysis(csv_back_output, os.path.join(folder_output, 'back'))
