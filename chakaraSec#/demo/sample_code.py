#!/usr/bin/env python3
"""
Sample protected code for ChakraSec demonstration
This code will be encrypted with 7-layer protection
"""

def financial_calculation():
    """Sensitive financial calculation"""
    print("=== FINANCIAL VAULT ACCESS GRANTED ===")
    print("Accessing confidential financial data...")
    
    # Simulate sensitive financial operations
    account_balance = 1000000.50
    interest_rate = 0.025
    
    print(f"Account Balance: ${account_balance:,.2f}")
    print(f"Interest Rate: {interest_rate:.3%}")
    
    # Calculate compound interest
    years = 5
    future_value = account_balance * (1 + interest_rate) ** years
    
    print(f"Projected Value (5 years): ${future_value:,.2f}")
    print("=== END FINANCIAL CALCULATION ===")
    
    return {
        "current_balance": account_balance,
        "projected_value": future_value,
        "calculation_date": "2024-01-01"
    }

def medical_records_access():
    """Access to sensitive medical records"""
    print("=== MEDICAL RECORDS ACCESS GRANTED ===")
    print("Retrieving patient medical records...")
    
    # Simulate medical data access
    patient_data = {
        "patient_id": "P123456",
        "name": "John Doe",
        "condition": "Hypertension",
        "medication": "Lisinopril 10mg",
        "last_visit": "2024-01-15",
        "next_appointment": "2024-02-15"
    }
    
    for key, value in patient_data.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    
    print("=== END MEDICAL RECORDS ACCESS ===")
    return patient_data

def trade_secrets_access():
    """Access to corporate trade secrets"""
    print("=== TRADE SECRETS ACCESS GRANTED ===")
    print("Accessing confidential corporate information...")
    
    # Simulate trade secret data
    secrets = {
        "formula": "C8H10N4O2 + Secret Catalyst X",
        "market_strategy": "Expand to Asia-Pacific Q2 2024",
        "acquisition_target": "TechStartup Inc - $50M valuation",
        "product_roadmap": "AI Integration by Q4 2024"
    }
    
    for secret_type, secret_value in secrets.items():
        print(f"{secret_type.replace('_', ' ').title()}: {secret_value}")
    
    print("=== END TRADE SECRETS ACCESS ===")
    return secrets

def development_environment():
    """Development environment access"""
    print("=== DEVELOPMENT ENVIRONMENT ACCESS ===")
    print("Welcome to the development environment!")
    
    # Simulate development tools
    tools = [
        "Code Editor: VSCode",
        "Version Control: Git",
        "Database: PostgreSQL Dev Instance",
        "API Testing: Postman",
        "Monitoring: Local Grafana"
    ]
    
    print("Available Development Tools:")
    for tool in tools:
        print(f"  - {tool}")
    
    print("=== DEVELOPMENT ENVIRONMENT READY ===")
    return {"status": "ready", "tools": tools}

# Main execution logic
if __name__ == "__main__":
    print("ChakraSec Protected Code Execution")
    print("=" * 50)
    
    # This code will only execute after all 7 layers are successfully decrypted
    # and all policy requirements are met
    
    import sys
    
    # Determine which function to run based on context
    # In a real implementation, this would be determined by the asset type
    
    # For demonstration, run all functions
    try:
        print("\n1. Financial Calculation:")
        financial_result = financial_calculation()
        
        print("\n2. Medical Records:")
        medical_result = medical_records_access()
        
        print("\n3. Trade Secrets:")
        trade_result = trade_secrets_access()
        
        print("\n4. Development Environment:")
        dev_result = development_environment()
        
        print("\n" + "=" * 50)
        print("All protected operations completed successfully!")
        print("ChakraSec 7-layer protection verified.")
        
    except Exception as e:
        print(f"Error during protected execution: {e}")
        sys.exit(1)
