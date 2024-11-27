package netology.dao_hibernate.entity;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;


@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Embeddable
public class PersonID implements Serializable {
    @Column(length = 40, name = "name", nullable = false)
    private String name;
    @Column(length = 40, name = "surname", nullable = false)
    private String surname;
    @Column(length = 5, name = "age", nullable = false)
    private int age;

}