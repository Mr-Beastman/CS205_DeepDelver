class EntropyAnalyser:

    def __init__(self, entropyResults: dict):
        self.shannon = entropyResults.get("shannon")
        self.part = entropyResults.get("part", {})

    def analyseEntropy(self) -> dict:
        """
        Review extracted data and classify
        """

        if self.shannon is not None:
            if self.shannon > 7.8:
                shannonSeverity = "high"
                shannonDesc = f"Very high entropy detected, likely packed or encrypted."
                level = "Very High"
            elif self.shannon > 7.4:
                shannonSeverity = "medium"
                shannonDesc = f"High entropy, possibly packed."
                level = "High"
            elif self.shannon > 7.0:
                shannonSeverity = "low"
                shannonDesc = f"Slightly elevated entropy."
                level = "Elevated"
            else:
                shannonSeverity = "info"
                shannonDesc = f"Normal entropy."
                level = "Normal"
        else:
            shannonSeverity = "info"
            shannonDesc = "Shannon entropy unavailable."
            level = "Unknown"

        shannonStruct = {
            "metric": "Shannon Entropy",
            "value": round(self.shannon, 4) if self.shannon is not None else None,
            "severity": shannonSeverity,
            "indicator": shannonDesc
        }

        spikes = [v for v in self.part.values() if v > 0.09]
        spikeCount = len(spikes)

        if spikeCount > 20:
            spikeSeverity = "medium"
            spikeDesc = f"Detected {spikeCount} high-entropy byte windows (>0.09), suggesting encrypted/packed regions."
        elif spikeCount > 5:
            spikeSeverity = "low"
            spikeDesc = f"Detected {spikeCount} slightly elevated entropy regions."
        else:
            spikeSeverity = "info"
            spikeDesc = f"Low number of entropy spike regions ({spikeCount})."

        spikeStruct = {
            "metric": "Local Entropy Spikes",
            "value": spikeCount,
            "severity": spikeSeverity,
            "indicator": spikeDesc
        }


        overallSeverity = (
            "high" if shannonSeverity == "high" else
            "medium" if spikeSeverity == "medium" else
            "low" if shannonSeverity == "low" else
            "info"
        )

        summary = {
            "entropyLevel": level,
            "totalSpikes": spikeCount,
            "severity": overallSeverity
        }

        return {
            "summary": summary,
            "shannon": shannonStruct,
            "spikes": spikeStruct
        }
