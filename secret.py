import pandas as pd

class RealTimeData:
    def get_cleaned_real_time_data(self):
        path = "cleaned_dataset.csv"
        df = pd.read_csv(path)

        return df.iloc[177096]
    
if __name__ == "__main__":
    print(RealTimeData().get_cleaned_real_time_data())
