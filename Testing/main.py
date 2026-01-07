# main.py
import pandas as pd
from Testing.llm_init_openrouter import LLMClient
import os
from dotenv import load_dotenv

load_dotenv()

data_path = "../fake_dataset"
output = "./output_gemini-2.5-flash"

model_name = os.getenv('MODEL_NAME',"mistralai/mistral-7b-instruct")
def analyze_security_log(file_path: str, output_path: str):
    # Load CSV
    df = pd.read_csv(file_path)
    print(f"Loaded {len(df)} log entries from {file_path}")

    # Initialize LLM client (OpenRouter)
    # llm = LLMClient(model="x-ai/grok-4-fast:free")
    llm = LLMClient(model=model_name)


    # Convert CSV to string
    csv_text = df.to_csv(index=False)

    # Analyze all logs at once
    analysis_results = llm.analyze_logs(csv_text)

    # Convert results to DataFrame
    analysis_df = pd.DataFrame(analysis_results)

    # Merge and export
    result_df = pd.concat([df, analysis_df], axis=1)
    print("\nAnalysis complete. Preview:")
    print(result_df.head())

    result_df.to_csv(output_path, index=False,  encoding="utf-8-sig")
    print(f"Saved analyzed results to {output_path}")

def convert_csv_encoding(input_path, output_path, encoding_out="utf-8-sig"):
    print(f"Converting: {input_path} -> {output_path} ({encoding_out})")
    df = pd.read_csv(input_path, encoding="utf-8", on_bad_lines="skip")
    df.to_csv(output_path, index=False, encoding=encoding_out)
    print("Done.")

def main():
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Input folder '{data_path}' not found")

    csv_files = [f for f in os.listdir(data_path) if f.endswith(".csv")]

    if not csv_files:
        print(f"No CSV files found in {data_path}")
        return

    print(f"Found {len(csv_files)} CSV files in '{data_path}'")

    # for filename in csv_files:
    #     input_path = os.path.join(data_path, filename)
    #     output_path = os.path.join(output, f"analyzed_{filename}")
    #     analyze_security_log(input_path, output_path)
    #     convert_csv_encoding(output_path, output_path)
    filename = "network_logs_with_label.csv"
    input_path = data_path + f"/{filename}"
    output_path = output + f"/analyzed_{filename}"
    analyze_security_log(input_path, output_path)
    convert_csv_encoding(output_path, output_path)


if __name__ == "__main__":
    main()
