alice = [0.27, 0.079, 0.27, 0.36, 0.25, 0.3, 0.27, 0.17, 0.23, 0.12, 0.29, 0.085, 0.093, 0.12, 0, 0.34, 0.23, 0.12,
0.34, 0.029, 0.19, 0.18, 0.23, 0.23, 0.11, 0.2, 0.18, 0.26, 0.31, 0.31, 0.11, 0.21, 0.079, 0.089, 0.2,
0.35, 0.12, 0.24, 0.18, 0.31, 0.091, 0.2, 0.26, 0.31, 0.35, 0.21, 0.051, 0.13, 0.094, 0.44, 0.14, 0.27,
0.18, 0.29, 0.12, 0.06, 0.058, 0.25, 0.18, 0.18, 0.34, 0.23, 0.22, 0.36, 0.12, 0.27, 0.28, 0.18, 0.22,
0.083, 0.085, 0.21, 0.27, 0.46, 0.13, 0.22, 0.19, 0.0067, 0.16, 0.021, 0.28, 0.11, 0.21, 0.15, 0.23, 0.14,
0.25, 0.27, 0.37, 0.18, 0, 0.12, 0.34, 0.093, 0.3, 0.21, 0.34, 0.0039, 0.18, 0.079]

eve = [1.2, 0.77, 0.88, 0.39, 0.51, 0.55, 0.82, 0.54, 0.74, 0.19, 0.53, 0.44, 0.28, 0.7, 0.66, 0.61, 0.33, 0.83,
0.67, 0.54, 0.6, 0.55, 0.25, 0.54, 0.43, 0.4, 0.37, 0.49, 0.2, 0.79, 0.7, 0.6, 0.59, 0.44, 0.8, 0.57, 0.46,
0.87, 0.56, 0.48, 0.54, 0.43, 0.38, 1.1, 0.93, 0.66, 0.35, 0.43, 0.56, 0.76, 0.33, 0.13, 0.31, 0.67, 0.68,
0.69, 0.57, 0.64, 0.5, 0.77, 0.33, 0.69, 0.43, 0.53, 0.71, 0.81, 0.38, 0.85, 0.73, 0.59, 0.56, 0.56, 0.54,
0.6, 0.61, 0.77, 0.91, 0.69, 0.56, 0.73, 0.64, 0.39, 0.79, 0.66, 0.63, 0.7, 0.65, 0.41, 0.57, 0.57, 0.49,
0.94, 0.42, 0.5, 0.46, 0.37, 0.56, 0.55, 0.91, 0.55]

threshold = [0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55]


def calculateLogin(threshold):
    aliceValid = 0
    eveValid = 0
    for i in alice:
        if i < threshold:
            aliceValid += 1
    for i in eve:
        if i < threshold:
            eveValid += 1
    return aliceValid, eveValid

for i in threshold:
    aliceValid, eveValid = calculateLogin(i)
    print("Threshold: " + str(i) + " Alice: " + str(aliceValid) + " Eve: " + str(eveValid))
    print("Means there's " + str(aliceValid) + " valid logins for Alice and " + str(eveValid) + " valid logins for Eve")
    print("With this threshold, we have " + str(len(alice) - aliceValid) + " invalid logins for Alice and " + str(eveValid) + " false positive for Eve that could connect to eve account")
    print("The false reject rate of this threshold is " + str((len(alice) - aliceValid)/len(alice)) + " and the false positive rate is " + str(eveValid/len(eve)))
    print("")