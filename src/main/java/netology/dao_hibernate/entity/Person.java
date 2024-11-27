package netology.dao_hibernate.entity;

import javax.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Table(name = "persons")
@NamedNativeQuery(
        name = "findPersonByCity",
        query = "select * from persons p where p.city_of_living = :city"
)
public class Person {
    @EmbeddedId
    private PersonID contact;
    @Column(length = 20, name = "phone_number", nullable = false)
    private String phoneNumber;
    @Column(length = 30, name = "city_of_living", nullable = false)
    private String cityOfLiving;


}