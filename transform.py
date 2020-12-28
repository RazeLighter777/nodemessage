import re

def interpretPost(text):
    text = str(text)
    reactivators = ""
    startModifiers = ["[b]", "[u]", "[r]", "[d]"]
    endModifiers = ["[~b]","[~u]", "[~r]", "[~d]"]
    codes = ["1m", "4m", "7m", "2m"]
    activities = [False, False, False, False]
    i = 0
    while i < len(text):
        for j in range(len(startModifiers)):
            if text[i : i + len(startModifiers[j])] == startModifiers[j]:
                activities[j] = True
                firstSubstring = text[0 : i]
                secondSubstring = text[i + len(startModifiers[j]):len(text)]
                text = firstSubstring + "\u001b[" + codes[j] + secondSubstring
                break
        for k in range(len(endModifiers)):
            if text[i:i + len(endModifiers[k])] == endModifiers[k]:
                activities[k] = False
                firstSubstring = text[0 : i]
                secondSubstring = text[i + len(endModifiers[k]):len(text)]
                for u in range(len(startModifiers)):
                    if activities[u]:
                        reactivators = reactivators + "\u001b[" + codes[u]
                text = firstSubstring + "\u001b[0m" + reactivators + secondSubstring
                reactivators = ""
        i += 1
    
    return text
                
print(interpretPost("[d]Reversed Text[~d]"))



    