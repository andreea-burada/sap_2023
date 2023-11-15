package day02;

public class Certificate {
    String name;
    String organization;
    String country;
    String signature;

    public Certificate
            (String name,
             String organization,
             String country,
             String signature
            ) {
        super();
        this.name = name;
        this.organization = organization;
        this.country = country;
        this.signature = signature;
    }

    @Override
    public int hashCode() {
        return this.signature.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null)
            return false;
        if (this == obj)
            return true;
        if (!(obj instanceof Certificate))
            return false;
        return this.name.equals(((Certificate)obj).name) && this.signature.equals(((Certificate)obj).signature);
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return new Certificate(
                this.name,
                this.organization,
                this.country,
                this.signature
        );
    }

    @Override
    public String toString() {
        return this.name + " with signature " + this.signature;
    }
}
