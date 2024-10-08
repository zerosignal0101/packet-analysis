# Packet analysis tool
A tool for packet analysis from both production environment and replay environment.

Particularly we specify 'back' as the replay environment.

## Environments

### Docker installation

#### Build image

```shell
docker compose build
```

#### Run the image

```shelll
docker compose up
```

### Manual installation

#### Install PDM (If not install)

```shell
pip install pdm
```

#### Install the required packages

```shell
pdm install
```

#### Install Redis

Install redis. Then, run redis on port 6379.

#### Run celery worker

```shell
pdm run celery -A src.server.celery worker --loglevel=info -P eventlet
```

#### Run API interface

```shell
pdm run python src/server.py
```

## Command line usage (deprecated)

Make sure that the environment has been set up via `Mannual installation` part.

### Command line

#### Preprocess the dataset

```shell
pdm run python src/run.py -ip "raw_data/1test.pcap, raw_data/2.pcap" -ib 'raw_data\test2.pcap' --method preprocess
```

This process will extract essential fields from the captured packets to csv files. It will generate 2 files `extracted_production_data.csv` and `extracted_back_data.csv` in `results` folder.

#### Align the output csv

```shell
pdm run python src/run.py -ip "results\extracted_production_data.csv" -ib "results\extracted_back_data.csv" --method align
```
This process will align the requests from production environment and back environment based on query and path. It will generate 1 file `aligned_output.csv` in `results` folder. 

#### Cluster analysis

```shell
pdm run python src/run.py -ip "results\extracted_production_data.csv" -ib "results\extracted_back_data.csv" --method analysis
```
This process will analysis the data from production environment with cluster algorithm. It will generate plots in `results/cluter_plots` folder. 