# Packet analysis tool
A tool for packet analysis from both production environment and replay environment.

Particularly we specify 'back' as the replay environment.

## Init

### Install pdm (If not install)
```shell
pip install pdm
```

### Install the required packages
```shell
pdm install
```

## Usage
### Preprocess the dataset
```shell
pdm run python main.py -i 'raw_data\test1.pcap' 'raw_data\test2.pcap' --method preprocess
```

This process will extract essential fields from the captured packets to csv files. It will generate 2 files `extracted_production_data.csv` and `extracted_back_data.csv` in `results` folder.

### Align the output csv
```shell
pdm run python main.py -i 'results\extracted_production_data.csv' 'results\extracted_back_data.csv' --method align
```
This process will align the requests from production environment and back environment based on query and path. It will generate 1 file `aligned_output.csv` in `results` folder. 

### Cluster analysis
```shell
pdm run python main.py -i 'results\extracted_production_data.csv' 'results\extracted_back_data.csv' --method analysis
```
This process will analysis the data from production environment with cluster algorithm. It will generate plots in `results/cluter_plots` folder. 