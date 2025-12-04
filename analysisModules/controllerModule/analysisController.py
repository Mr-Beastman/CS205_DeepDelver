import subprocess
from pathlib import Path
from analysisModules.staticModules.controllerModule.staticController import StaticController
from analysisModules.dynamicModules.controllerModules.dynamicController import DynamicController
from analysisModules.riskModule.riskAnalyser import RiskAnalyser


def runFullAnalysis(filePath: str):
    exePath = Path(filePath)

    # static analysis
    staticCtrl = StaticController(str(exePath))
    staticCtrl.runStaticAnalysis()
    staticResults = staticCtrl.combineResults()

    # dynamic analysis
    dynamicCtrl = DynamicController(str(exePath))

    # Start monitoring BEFORE execution
    dynamicCtrl.startDynamicAnalysis()

    # Launch process safely & monitor runtime
    process = subprocess.Popen([str(exePath)], shell=False)

    process.wait()

    # Stop monitoring after execution completes
    dynamicCtrl.stopDynamicAnalysis()
    dynamicResults = dynamicCtrl.combineResults()

    # combine results
    print("> Combining Analysis Results")
    combinedResults = {
        "StaticAnalysis": staticResults,
        "DynamicAnalysis": dynamicResults
    }

    # risk scoring
    print("=== Starting Analysis Scoring ===")
    riskAnalyser = RiskAnalyser(combinedResults)
    riskReport = riskAnalyser.calculateRisk()
    print("> Results Scored")

    return {
        "CombinedResults": combinedResults,
        "RiskReport": riskReport
    }
