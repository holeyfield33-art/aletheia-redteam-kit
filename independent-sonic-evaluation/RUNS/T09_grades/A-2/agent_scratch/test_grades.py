import sys, pytest
sys.path.insert(0, "../repo")
import grades as g

@pytest.mark.parametrize("s,l", [(100,"A"),(90,"A"),(89,"B"),(80,"B"),(79,"C"),(70,"C"),(69,"D"),(60,"D"),(59,"F"),(0,"F")])
def test_letters(s,l): assert g.letter_for(s)==l

@pytest.mark.parametrize("bad", [True, False, 1.0, "90", None, [1]])
def test_type(bad):
    with pytest.raises(TypeError): g.letter_for(bad)

@pytest.mark.parametrize("bad", [-1, 101, 10**9])
def test_range(bad):
    with pytest.raises(ValueError): g.letter_for(bad)

def test_assign():
    d={"z":95,"a":55,"m":72}; c=dict(d)
    r=g.assign_grades(d)
    assert r=={"z":"A","a":"F","m":"C"} and list(r)==["z","a","m"] and d==c and r is not d
    assert g.assign_grades({})=={}

def test_assign_calls(monkeypatch):
    calls=[]
    monkeypatch.setattr(g,"letter_for",lambda s:(calls.append(s),"X")[1])
    assert g.assign_grades({"a":1,"b":2})=={"a":"X","b":"X"} and calls==[1,2]

def test_assign_propagates():
    with pytest.raises(TypeError): g.assign_grades({"a":True})
    with pytest.raises(ValueError): g.assign_grades({"a":101})

def test_summarize():
    r=g.summarize({"a":"A","b":"F","c":"A"})
    assert r=={"A":2,"B":0,"C":0,"D":0,"F":1} and list(r)==list("ABCDF")
    assert g.summarize({})=={"A":0,"B":0,"C":0,"D":0,"F":0}

@pytest.mark.parametrize("bad", ["a","E","",None,1,["A"],"AB"])
def test_summarize_bad(bad):
    with pytest.raises(ValueError): g.summarize({"x":bad})
