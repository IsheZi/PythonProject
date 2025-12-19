import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

class DataCharts:
    def __init__(self):
        self.df = None

    def set_df(self, df: pd.DataFrame):
        """
        Safely set the DataFrame and convert known date columns
        to datetime with explicit format to avoid warnings.
        """
        date_columns = ["date", "created_date"]
        for col in date_columns:
            if col in df.columns:
                try:
                    df[col] = pd.to_datetime(df[col], format="%Y-%m-%d", errors="coerce")
                except Exception:
                    # leave column as-is if conversion fails
                    pass
        self.df = df

    def generate_charts(self, output_dir="charts", show=False):
        if self.df is None or self.df.empty:
            print("⚠️ No data available to generate charts.")
            return []

        os.makedirs(output_dir, exist_ok=True)
        files = []

        # Histogram of severity
        if "severity" in self.df.columns:
            plt.figure()
            sns.countplot(x=self.df["severity"], order=self.df["severity"].value_counts().index)
            plt.title("Histogram of Incident Severity")
            path = os.path.join(output_dir, "hist_severity.png")
            plt.savefig(path, bbox_inches="tight")
            plt.close()
            files.append(path)

        # Bar chart of dataset_name
        if "dataset_name" in self.df.columns:
            plt.figure()
            sns.countplot(y=self.df["dataset_name"], order=self.df["dataset_name"].value_counts().index)
            plt.title("Datasets by Name")
            path = os.path.join(output_dir, "bar_dataset_name.png")
            plt.savefig(path, bbox_inches="tight")
            plt.close()
            files.append(path)

        # Pie chart of status
        if "status" in self.df.columns:
            plt.figure()
            self.df["status"].value_counts().plot.pie(autopct="%1.1f%%")
            plt.title("Incident Status Distribution")
            path = os.path.join(output_dir, "pie_status.png")
            plt.savefig(path, bbox_inches="tight")
            plt.close()
            files.append(path)

        # Scatter matrix (guarded)
        try:
            from pandas.plotting import scatter_matrix
            numeric_cols = self.df.select_dtypes(include="number").columns
            if len(numeric_cols) >= 2:
                scatter_matrix(self.df[numeric_cols].dropna(), diagonal="kde", figsize=(8, 8))
                path = os.path.join(output_dir, "scatter_matrix.png")
                plt.savefig(path, bbox_inches="tight")
                plt.close()
                files.append(path)
        except ImportError:
            print("⚠️ Skipping scatter matrix (SciPy not installed).")

        print(f"✅ Generated {len(files)} charts: {', '.join(os.path.basename(f) for f in files)}")
        return files