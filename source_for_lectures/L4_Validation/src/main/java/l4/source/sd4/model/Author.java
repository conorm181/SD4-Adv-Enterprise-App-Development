
package l4.source.sd4.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Entity
public class Author  {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long authorID;
    private String firstName;
    private String lastName;
    private int yearBorn;
}

