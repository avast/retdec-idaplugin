CO=user_guide

all: $(CO).pdf

$(CO).pdf: $(CO).tex
	pdflatex -draftmode $(CO).tex
	pdflatex $(CO).tex

clean:
	rm -f *.dvi *.ps *.log $(CO).blg $(CO).bbl $(CO).toc *.aux $(CO).out $(CO).lof $(CO).lot
	rm -f $(CO).pdf
	rm -f *~
